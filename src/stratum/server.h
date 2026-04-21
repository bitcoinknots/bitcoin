// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_STRATUM_SERVER_H
#define BITCOIN_STRATUM_SERVER_H

#include <stratum/jobmanager.h>
#include <stratum/session.h>
#include <stratum/template_provider.h>
#include <sync.h>
#include <univalue.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>

class ArgsManager;
class Sock;

namespace interfaces {
class Mining;
}

namespace stratum {

// TODO(stratum): Add vardiff.
// TODO(stratum): Add Stratum V2 support.
// TODO(stratum): Add job declaration and miner-selected templates.
// TODO(stratum): Add pooled reward accounting.
// TODO(stratum): Add miner username -> payout address mode.
// TODO(stratum): Add external notification hooks / ZMQ integration.

struct Config {
    bool enabled{false};
    std::string bind{"127.0.0.1"};
    uint16_t port{3333};
    uint32_t extranonce2_size{4};
    double difficulty{1.0};
    std::string payout_address;
    bool version_rolling{false};
    uint32_t version_rolling_mask{0x1fffe000};
    int64_t job_refresh_ms{1000};
    bool allow_self_select{false};
};

struct Info {
    bool enabled{false};
    bool listening{false};
    bool accept_loop_running{false};
    std::string bind;
    uint16_t port{0};
    size_t clients{0};
    std::string current_job_id;
    int32_t current_height{0};
    std::string current_prevhash;
    uint64_t accepted_shares{0};
    uint64_t rejected_shares{0};
    uint64_t blocks_found{0};
    bool version_rolling_enabled{false};
    uint32_t version_rolling_mask{0};
};

class Server
{
public:
    Server(const Config& config, interfaces::Mining& mining);
    ~Server();

    bool Start();
    void Interrupt();
    void Stop();

    UniValue HandleMessage(uint64_t session_id, const UniValue& request);
    Session& GetOrCreateSession(uint64_t session_id);
    Info GetInfo() const;

private:
    bool InitListeningSocket();
    void ThreadRun();

    const Config m_config;
    TemplateProvider m_template_provider;
    JobManager m_job_manager;

    std::atomic<bool> m_running{false};
    std::atomic<bool> m_listening{false};
    std::atomic<bool> m_accept_loop_running{false};
    std::thread m_thread;
    std::unique_ptr<Sock> m_listen_socket;

    mutable Mutex m_mutex;
    std::unordered_map<uint64_t, std::unique_ptr<Session>> m_sessions GUARDED_BY(m_mutex);
    uint64_t m_accepted_shares GUARDED_BY(m_mutex){0};
    uint64_t m_rejected_shares GUARDED_BY(m_mutex){0};
    uint64_t m_blocks_found GUARDED_BY(m_mutex){0};
};

Config GetConfig(const ArgsManager& args, bool is_regtest);

} // namespace stratum

#endif // BITCOIN_STRATUM_SERVER_H
