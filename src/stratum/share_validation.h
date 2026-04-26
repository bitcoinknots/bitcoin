// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_STRATUM_SHARE_VALIDATION_H
#define BITCOIN_STRATUM_SHARE_VALIDATION_H

#include <stratum/session.h>
#include <stratum/stratum_messages.h>

#include <arith_uint256.h>
#include <uint256.h>

#include <string>

namespace stratum {

struct Job;

struct ShareValidationResult {
    bool accepted_share{false};
    bool accepted_block{false};
    std::string reject_reason;
    uint256 block_hash;
    arith_uint256 share_target;
    arith_uint256 network_target;
};

ShareValidationResult ValidateShare(const SubmitRequest& req, const Session& session, const Job& job);

} // namespace stratum

#endif // BITCOIN_STRATUM_SHARE_VALIDATION_H
