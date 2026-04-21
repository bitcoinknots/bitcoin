// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stratum/stratum_messages.h>

namespace stratum {

std::optional<SubmitRequest> ParseSubmitParams(const UniValue& params)
{
    if (!params.isArray() || (params.size() != 5 && params.size() != 6)) return std::nullopt;
    SubmitRequest req;
    req.worker_name = params[0].get_str();
    req.job_id = params[1].get_str();
    req.extranonce2 = params[2].get_str();
    req.ntime = params[3].get_str();
    req.nonce = params[4].get_str();
    if (params.size() == 6) req.version_bits = params[5].get_str();
    return req;
}

UniValue BuildSuccess(const UniValue& id, bool result)
{
    UniValue response(UniValue::VOBJ);
    response.pushKV("id", id);
    response.pushKV("result", result);
    response.pushKV("error", UniValue{UniValue::VNULL});
    return response;
}

UniValue BuildError(const UniValue& id, int code, const std::string& message)
{
    UniValue response(UniValue::VOBJ);
    response.pushKV("id", id);
    response.pushKV("result", false);
    UniValue err(UniValue::VARR);
    err.push_back(code);
    err.push_back(message);
    err.push_back(UniValue{UniValue::VNULL});
    response.pushKV("error", std::move(err));
    return response;
}

} // namespace stratum
