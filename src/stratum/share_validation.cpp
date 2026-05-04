// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stratum/share_validation.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <stratum/jobmanager.h>
#include <stratum/server.h>
#include <streams.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cmath>

namespace stratum {
namespace {
constexpr uint32_t DIFF1_BITS{0x1d00ffff};

uint256 HashConcat(const uint256& a, const uint256& b)
{
    HashWriter ss{};
    ss << a << b;
    return ss.GetHash();
}

uint32_t ParseHexU32(const std::string& s)
{
    size_t idx{0};
    return static_cast<uint32_t>(std::stoul(s, &idx, 16));
}

arith_uint256 GetDiff1Target()
{
    arith_uint256 diff1_target;
    bool fneg, fov;
    diff1_target.SetCompact(DIFF1_BITS, &fneg, &fov);
    assert(!fneg && !fov && diff1_target != 0);
    return diff1_target;
}

arith_uint256 GetShareTarget(double difficulty)
{
    constexpr uint64_t SCALE{100000000};
    arith_uint256 share_target = GetDiff1Target();

    // Difficulty is validated at config load, but clamp here defensively.
    if (!(std::isfinite(difficulty)) || difficulty <= 0.0) {
        return 0;
    }

    const uint64_t scaled = std::max<uint64_t>(1, static_cast<uint64_t>(difficulty * SCALE));
    share_target *= SCALE;
    share_target /= arith_uint256{scaled};
    return share_target;
}
} // namespace

ShareValidationResult ValidateShare(const SubmitRequest& req, const Session& session, const Job& job, const Config& config)
{
    ShareValidationResult ret;
    if (req.extranonce2.size() != session.extranonce2_size * 2) {
        ret.reject_reason = "invalid-extranonce2-size";
        return ret;
    }

    if (!IsHex(req.ntime) || !IsHex(req.nonce)) {
        ret.reject_reason = "invalid-hex-field";
        return ret;
    }

    uint32_t final_version = job.version;
    if (req.version_bits.has_value()) {
        if (!IsHex(req.version_bits.value())) {
            ret.reject_reason = "invalid-version-bits";
            return ret;
        }
        if (!config.version_rolling) {
            ret.reject_reason = "version-rolling-not-enabled";
            return ret;
        }
        const uint32_t submitted_version = ParseHexU32(req.version_bits.value());
        if ((submitted_version & ~config.version_rolling_mask) != (job.version & ~config.version_rolling_mask)) {
            ret.reject_reason = "invalid-version-bits-mask";
            return ret;
        }
        final_version = (job.version & ~config.version_rolling_mask) | (submitted_version & config.version_rolling_mask);
    }

    CBlockHeader header;
    header.nVersion = static_cast<int32_t>(final_version);

    header.hashPrevBlock = job.prevhash;
    header.nBits = job.nbits;
    try {
        header.nTime = ParseHexU32(req.ntime);
        header.nNonce = ParseHexU32(req.nonce);
    } catch (...) {
        ret.reject_reason = "invalid-nonce-or-ntime";
        return ret;
    }

    CMutableTransaction coinbase;
    try {
        const std::vector<unsigned char> coinbase_raw = ParseHex(job.coinb1 + session.extranonce1 + req.extranonce2 + job.coinb2);
        DataStream ds{coinbase_raw};
        ds >> TX_WITH_WITNESS(coinbase);
    } catch (...) {
        ret.reject_reason = "invalid-coinbase";
        return ret;
    }

    uint256 merkle = CTransaction{coinbase}.GetHash();
    for (const auto& h : job.merkle_branches) {
        merkle = HashConcat(merkle, h);
    }
    header.hashMerkleRoot = merkle;

    const arith_uint256 hash_val{UintToArith256(header.GetHash())};
    arith_uint256 network_target;
    bool fneg, fov;
    network_target.SetCompact(header.nBits, &fneg, &fov);
    if (fneg || fov || network_target == 0) {
        ret.reject_reason = "invalid-network-target";
        return ret;
    }
    const arith_uint256 share_target{GetShareTarget(session.difficulty)};

    ret.accepted_share = hash_val <= share_target;
    ret.accepted_block = hash_val <= network_target;
    ret.block_hash = header.GetHash();
    ret.final_version = final_version;
    ret.coinbase_hash = CTransaction{coinbase}.GetHash();
    ret.merkle_root = merkle;
    ret.share_target = share_target;
    ret.network_target = network_target;
    if (!ret.accepted_share) ret.reject_reason = "low-difficulty-share";
    return ret;
}

} // namespace stratum
