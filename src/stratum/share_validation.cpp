// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stratum/share_validation.h>
#include <hash.h>
#include <util/strencodings.h>
#include <crypto/sha256.h>
#include <stratum/jobmanager.h>
#include <util/strencodings.h>

namespace stratum {
namespace {
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
} // namespace

ShareValidationResult ValidateShare(const SubmitRequest& req, const Session& session, const Job& job, const arith_uint256& pow_limit)
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

    CBlockHeader header;
    header.nVersion = static_cast<int32_t>(job.version);
    if (req.version_bits.has_value()) {
        if (!IsHex(req.version_bits.value())) {
            ret.reject_reason = "invalid-version-bits";
            return ret;
        }
    }

    header.hashPrevBlock = job.prevhash;
    header.nBits = job.nbits;
    try {
        header.nTime = ParseHexU32(req.ntime);
        header.nNonce = ParseHexU32(req.nonce);
    } catch (...) {
        ret.reject_reason = "invalid-nonce-or-ntime";
        return ret;
    }

    uint256 merkle = job.block.vtx.at(0)->GetHash();
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

    arith_uint256 share_target = pow_limit;
    if (session.difficulty > 1) share_target /= static_cast<uint32_t>(session.difficulty);

    ret.accepted_share = hash_val <= share_target;
    ret.accepted_block = hash_val <= network_target;
    ret.block_hash = header.GetHash();
    if (!ret.accepted_share) ret.reject_reason = "low-difficulty-share";
    return ret;
}

} // namespace stratum
