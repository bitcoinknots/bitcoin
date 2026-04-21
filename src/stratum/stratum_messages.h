// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_STRATUM_MESSAGES_H
#define BITCOIN_STRATUM_MESSAGES_H

#include <univalue.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace stratum {

struct SubmitRequest {
    std::string worker_name;
    std::string job_id;
    std::string extranonce2;
    std::string ntime;
    std::string nonce;
    std::optional<std::string> version_bits;
};

std::optional<SubmitRequest> ParseSubmitParams(const UniValue& params);
UniValue BuildSuccess(const UniValue& id, bool result=true);
UniValue BuildError(const UniValue& id, int code, const std::string& message);

} // namespace stratum

#endif // BITCOIN_STRATUM_MESSAGES_H
