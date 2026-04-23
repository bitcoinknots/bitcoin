// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_STRATUM_SESSION_H
#define BITCOIN_STRATUM_SESSION_H

#include <cstdint>
#include <string>

namespace stratum {

struct Session {
    uint64_t session_id{0};
    bool subscribed{false};
    bool authorized{false};
    std::string extranonce1;
    uint32_t extranonce2_size{4};
    double difficulty{1.0};
    uint32_t version_rolling_mask{0};
    std::string worker_name;
    bool initial_messages_sent{false};

    uint64_t accepted{0};
    uint64_t rejected{0};
    uint64_t stale{0};
    int64_t last_submit_time{0};
};

} // namespace stratum

#endif // BITCOIN_STRATUM_SESSION_H
