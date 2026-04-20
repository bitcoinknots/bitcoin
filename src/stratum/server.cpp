// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stratum/server.h>

#include <common/args.h>
#include <logging.h>
#include <util/thread.h>

#include <chrono>
#include <utility>

namespace stratum {

Server::Server(Config config)
    : m_config(std::move(config)), m_job_manager(m_config.address, m_config.difficulty)
{
}

Server::~Server()
{
    Stop();
}

bool Server::Start()
{
    if (!m_config.enabled) return true;
    if (m_running.exchange(true)) return true;

    m_thread = std::thread(&util::TraceThread, "stratum", [this] { ThreadRun(); });
    LogPrintf("Stratum skeleton enabled on 0.0.0.0:%u (solo mode)\n", m_config.port);
    return true;
}

void Server::Interrupt()
{
    m_running.store(false);
}

void Server::Stop()
{
    Interrupt();
    if (m_thread.joinable()) {
        m_thread.join();
    }
}

UniValue Server::HandleMessage(const UniValue& request)
{
    UniValue response(UniValue::VOBJ);
    if (!request.isObject()) {
        response.pushKV("result", false);
        response.pushKV("error", "Malformed JSON request");
        return response;
    }

    const std::string method = request.exists("method") ? request["method"].get_str() : "";
    const UniValue id = request.exists("id") ? request["id"] : UniValue{UniValue::VNULL};
    const UniValue params = request.exists("params") ? request["params"] : UniValue{UniValue::VARR};

    if (method == "mining.subscribe") {
        return m_job_manager.HandleSubscribe(id);
    }

    if (method == "mining.authorize") {
        auto ret = m_job_manager.HandleAuthorize();
        ret.pushKV("id", id);
        return ret;
    }

    if (method == "mining.submit") {
        auto ret = m_job_manager.HandleSubmit(params);
        ret.pushKV("id", id);

        LOCK(m_callback_mutex);
        if (m_submit_hook) m_submit_hook(request);
        return ret;
    }

    response.pushKV("id", id);
    response.pushKV("result", false);
    UniValue err(UniValue::VARR);
    err.push_back(404);
    err.push_back("Method not found");
    err.push_back(UniValue{UniValue::VNULL});
    response.pushKV("error", std::move(err));
    return response;
}

void Server::SetNotifyHook(std::function<void(const UniValue&)> notify_hook)
{
    LOCK(m_callback_mutex);
    m_notify_hook = std::move(notify_hook);
}

void Server::SetShareSubmitHook(std::function<void(const UniValue&)> submit_hook)
{
    LOCK(m_callback_mutex);
    m_submit_hook = std::move(submit_hook);
}

void Server::ThreadRun()
{
    while (m_running.load()) {
        const Job job = m_job_manager.RefreshJob();
        const UniValue notify = m_job_manager.BuildNotify(job);

        LOCK(m_callback_mutex);
        if (m_notify_hook) {
            m_notify_hook(notify);
        } else {
            LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "Stratum notify: %s\n", notify.write());
        }

        UninterruptibleSleep(std::chrono::seconds{10});
    }
}

Config GetConfig(const ArgsManager& args)
{
    Config cfg;
    cfg.enabled = args.GetBoolArg("-stratum", false);
    cfg.port = static_cast<uint16_t>(args.GetIntArg("-stratumport", 3333));
    cfg.address = args.GetArg("-stratumaddress", "");
    cfg.difficulty = static_cast<uint32_t>(args.GetIntArg("-stratumdifficulty", 1));
    return cfg;
}

} // namespace stratum
