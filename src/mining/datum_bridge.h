// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.
#ifndef BITCOIN_MINING_DATUM_BRIDGE_H
#define BITCOIN_MINING_DATUM_BRIDGE_H

#include <cstdint>
#include <string>
#include <vector>

class ArgsManager;
class UniValue;
struct bilingual_str;

namespace node {
struct NodeContext;
}

namespace mining {

struct DatumMinerStatus {
    std::string worker;
    std::string remote_host;
    std::string user_agent;
    bool subscribed{false};
    bool authorized{false};
    uint64_t connected_since_ms{0};
    uint64_t current_difficulty{0};
    double estimated_hashrate_ths{0};
    uint64_t accepted_shares{0};
    uint64_t rejected_shares{0};
    uint64_t last_share_time_ms{0};
};

struct DatumStatusSnapshot {
    std::string status{"Disabled"};
    bool enabled{false};
    bool running{false};
    bool auth_required{false};
    std::string listen{"127.0.0.1"};
    uint16_t port{23334};
    std::string payout_address;
    std::string configured_payout_address;
    std::string coinbase_tag;
    std::string configured_coinbase_tag;
    uint64_t session_started_ms{0};
    bool mapping_requested{false};
    bool mapping_active{false};
    std::string mapping_protocol;
    std::string mapping_external;
    uint32_t mapping_lifetime{0};
    uint64_t mapping_updated_ms{0};
    std::string mapping_error;
    uint64_t share_difficulty{0};
    uint32_t clients{0};
    uint32_t subscribed_clients{0};
    uint32_t authorized_clients{0};
    uint64_t accepted_shares{0};
    uint64_t rejected_shares{0};
    uint64_t session_accepted_shares{0};
    uint64_t session_rejected_shares{0};
    uint64_t last_share_time_ms{0};
    double estimated_hashrate_ths{0};
    uint64_t current_height{0};
    std::string job_id;
    uint64_t job_created_ms{0};
    std::string previous_block_hash;
    uint32_t nbits{0};
    double network_difficulty{0};
    uint32_t transaction_count{0};
    uint32_t template_size{0};
    uint32_t template_weight{0};
    uint64_t coinbase_value{0};
    uint64_t last_template_update_ms{0};
    bool last_template_success{false};
    std::string last_template_error;
    uint64_t block_candidates{0};
    uint64_t block_submissions_accepted{0};
    uint64_t block_submissions_rejected{0};
    uint64_t last_block_time_ms{0};
    std::string last_block_hash;
    std::string last_block_result;
    uint64_t last_rejected_share_time_ms{0};
    std::string last_rejected_share_reason;
    uint64_t rejected_unknown_work{0};
    uint64_t rejected_high_hash{0};
    uint64_t rejected_stale{0};
    uint64_t rejected_duplicate{0};
    uint64_t rejected_other{0};
    std::vector<DatumMinerStatus> miners;
};

void SetupDatumArgs(ArgsManager& argsman);
bool ValidateDatumOptions(const ArgsManager& args, bilingual_str& error);
bool StartDatum(node::NodeContext& node, bilingual_str& error);
void InterruptDatum();
void StopDatum(node::NodeContext* node = nullptr);
DatumStatusSnapshot GetDatumStatusSnapshot(bool include_miners = true);
UniValue GetDatumInfo();
bool SetDatumDifficulty(int64_t difficulty, std::string& error);
bool SetDatumPayoutAndCoinbase(const std::string& address, const std::string& coinbase_tag, std::string& error);

} // namespace mining

#endif // BITCOIN_MINING_DATUM_BRIDGE_H
