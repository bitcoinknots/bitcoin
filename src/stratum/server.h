// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_STRATUM_SERVER_H
#define BITCOIN_STRATUM_SERVER_H

#include <stratum/jobmanager.h>
#include <sync.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

class ArgsManager;

namespace stratum {

struct Config {
    bool enabled{false};
    uint16_t port{3333};
    std::string address;
    uint32_t difficulty{1};
};

class Server
{
public:
    explicit Server(Config config);
    ~Server();

    bool Start();
    void Interrupt();
    void Stop();

    UniValue HandleMessage(const UniValue& request);

    void SetNotifyHook(std::function<void(const UniValue&)> notify_hook);
    void SetShareSubmitHook(std::function<void(const UniValue&)> submit_hook);

private:
    void ThreadRun();

    const Config m_config;
    JobManager m_job_manager;

    std::atomic<bool> m_running{false};
    std::thread m_thread;

    mutable Mutex m_callback_mutex;
    std::function<void(const UniValue&)> m_notify_hook GUARDED_BY(m_callback_mutex);
    std::function<void(const UniValue&)> m_submit_hook GUARDED_BY(m_callback_mutex);
};

Config GetConfig(const ArgsManager& args);

} // namespace stratum

#endif // BITCOIN_STRATUM_SERVER_H
