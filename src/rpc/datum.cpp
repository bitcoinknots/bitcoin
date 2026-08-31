// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.
#include <mining/datum_bridge.h>

#include <rpc/server.h>
#include <rpc/util.h>

namespace {
RPCHelpMan getdatuminfo()
{
    return RPCHelpMan{
        "getdatuminfo",
        "Returns non-secret embedded DATUM/Stratum status.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", /*optional=*/false, "DATUM status", {
            {RPCResult::Type::BOOL, "enabled", "Whether DATUM is enabled at runtime"},
            {RPCResult::Type::BOOL, "running", "Whether the embedded subsystem is running"},
            {RPCResult::Type::STR, "status", "Lifecycle status"},
            {RPCResult::Type::STR, "listen", "Configured Stratum listen address"},
            {RPCResult::Type::NUM, "port", "Configured Stratum listen port"},
            {RPCResult::Type::BOOL, "upnp", "Whether DATUM UPnP mapping is configured"},
            {RPCResult::Type::BOOL, "auth_required", "Whether Stratum authentication is required"},
            {RPCResult::Type::NUM, "clients", "Connected Stratum clients"},
            {RPCResult::Type::NUM, "subscribed_clients", "Subscribed Stratum clients"},
            {RPCResult::Type::NUM, "authorized_clients", "Authorized Stratum clients"},
            {RPCResult::Type::NUM, "share_difficulty", "Fixed Stratum share difficulty"},
            {RPCResult::Type::NUM, "accepted_shares", "Accepted shares for currently connected clients"},
            {RPCResult::Type::NUM, "rejected_shares", "Rejected shares for currently connected clients"},
            {RPCResult::Type::NUM, "session_accepted_shares", "Accepted shares in this DATUM run"},
            {RPCResult::Type::NUM, "session_rejected_shares", "Rejected shares in this DATUM run"},
            {RPCResult::Type::NUM_TIME, "session_started", "DATUM run start time, or zero"},
            {RPCResult::Type::NUM_TIME, "last_share_time", "Last accepted share time, or zero"},
            {RPCResult::Type::NUM, "estimated_hashrate_ths", "Estimated total miner hashrate in TH/s"},
            {RPCResult::Type::NUM, "current_height", "Current mining job height, or zero"},
            {RPCResult::Type::OBJ, "port_mapping", "DATUM port mapping status", {
                {RPCResult::Type::BOOL, "requested", "Whether mapping was requested"},
                {RPCResult::Type::BOOL, "active", "Whether a mapping is active"},
                {RPCResult::Type::STR, "protocol", "UPnP, PCP, NAT-PMP, or empty"},
                {RPCResult::Type::STR, "external", "External endpoint, or empty"},
                {RPCResult::Type::NUM, "lifetime", "Granted lifetime in seconds, or zero"},
                {RPCResult::Type::NUM_TIME, "updated", "Last mapping update time, or zero"},
                {RPCResult::Type::STR, "error", "Sanitized last mapping error"},
            }},
            {RPCResult::Type::OBJ, "current_job", "Current mining job summary", {
                {RPCResult::Type::STR, "id", "Stratum job id"},
                {RPCResult::Type::NUM, "height", "Template height"},
                {RPCResult::Type::NUM_TIME, "created", "Job creation time, or zero"},
                {RPCResult::Type::STR_HEX, "previous_block_hash", "Previous block hash"},
                {RPCResult::Type::STR_HEX, "nbits", "Compact network target"},
                {RPCResult::Type::NUM, "network_difficulty", "Network difficulty derived from nBits"},
                {RPCResult::Type::NUM, "transactions", "Template transaction count"},
                {RPCResult::Type::NUM, "size", "Template transaction size in bytes"},
                {RPCResult::Type::NUM, "weight", "Template transaction weight"},
                {RPCResult::Type::NUM, "coinbase_value", "Coinbase value in satoshis"},
                {RPCResult::Type::NUM_TIME, "last_template_update", "Last template result time, or zero"},
                {RPCResult::Type::BOOL, "last_template_success", "Whether the last template fetch succeeded"},
                {RPCResult::Type::STR, "last_template_error", "Sanitized last template error"},
            }},
            {RPCResult::Type::OBJ, "block_submission", "Block candidate and diagnostic summary", {
                {RPCResult::Type::NUM, "candidates", "Block candidates found in this DATUM run"},
                {RPCResult::Type::NUM, "accepted", "Primary block submissions accepted"},
                {RPCResult::Type::NUM, "rejected", "Primary block submissions rejected"},
                {RPCResult::Type::NUM_TIME, "last_time", "Last block candidate result time, or zero"},
                {RPCResult::Type::STR_HEX, "last_hash", "Last block candidate hash"},
                {RPCResult::Type::STR, "last_result", "Sanitized last block result"},
                {RPCResult::Type::NUM_TIME, "last_share_rejection_time", "Last rejected share time, or zero"},
                {RPCResult::Type::STR, "last_share_rejection_reason", "Last rejected share reason"},
                {RPCResult::Type::OBJ, "share_rejections", "Rejected share reasons in this DATUM run", {
                    {RPCResult::Type::NUM, "unknown_work", "Unknown-work rejections"},
                    {RPCResult::Type::NUM, "high_hash", "High-hash rejections"},
                    {RPCResult::Type::NUM, "stale", "Stale-work rejections"},
                    {RPCResult::Type::NUM, "duplicate", "Duplicate-share rejections"},
                    {RPCResult::Type::NUM, "other", "Other share rejections"},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("getdatuminfo", "")},
        [&](const RPCHelpMan&, const JSONRPCRequest&) -> UniValue {
            return mining::GetDatumInfo();
        },
    };
}

RPCHelpMan setdatumdiff()
{
    return RPCHelpMan{
        "setdatumdiff",
        "Updates the embedded DATUM Stratum share difficulty without restarting. The setting is runtime-only; restart uses -datumdiff again.\n",
        {
            {"difficulty", RPCArg::Type::NUM, RPCArg::Optional::NO, "Fixed Stratum share difficulty (1 to 2147483647)."},
        },
        RPCResult{RPCResult::Type::OBJ, "", /*optional=*/false, "Applied DATUM share difficulty", {
            {RPCResult::Type::NUM, "difficulty", "The new runtime share difficulty"},
        }},
        RPCExamples{HelpExampleCli("setdatumdiff", "1024")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const int64_t difficulty{request.params[0].getInt<int64_t>()};
            std::string error;
            if (!mining::SetDatumDifficulty(difficulty, error)) {
                throw JSONRPCError(RPC_MISC_ERROR, error);
            }
            UniValue result{UniValue::VOBJ};
            result.pushKV("difficulty", difficulty);
            return result;
        },
    };
}
} // namespace

void RegisterDatumRPCCommands(CRPCTable& table)
{
    static const CRPCCommand commands[]{
        {"mining", &getdatuminfo},
        {"mining", &setdatumdiff},
    };
    for (const auto& command : commands) table.appendCommand(command.name, &command);
}
