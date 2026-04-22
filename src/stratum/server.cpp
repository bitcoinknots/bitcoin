// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stratum/server.h>
#include <sys/socket.h>

#include <common/args.h>
#include <interfaces/mining.h>
#include <logging.h>
#include <netbase.h>
#include <stratum/share_validation.h>
#include <stratum/stratum_messages.h>
#include <util/sock.h>
#include <util/thread.h>

#include <chrono>

namespace stratum {
namespace {
uint32_t ParseHexU32(const std::string& s, uint32_t def)
{
    try {
        size_t idx{0};
        const uint32_t out = static_cast<uint32_t>(std::stoul(s, &idx, 16));
        return idx == s.size() ? out : def;
    } catch (...) {
        return def;
    }
}
} // namespace

Server::Server(const Config& config, interfaces::Mining& mining)
    : m_config(config),
      m_template_provider(mining),
      m_job_manager(m_template_provider, m_config.extranonce2_size, m_config.payout_address)
{
}

Server::~Server()
{
    Stop();
}

bool Server::InitListeningSocket()
{
    const auto bind_addr = Lookup(m_config.bind, m_config.port, /*fAllowLookup=*/false);
    if (!bind_addr.has_value() || !bind_addr->IsValid()) {
        LogPrintf("Stratum bind failed: unable to resolve bind address '%s:%u'\n", m_config.bind, m_config.port);
        return false;
    }

    struct sockaddr_storage servaddr;
    socklen_t len = sizeof(servaddr);
    if (!bind_addr->GetSockAddr(reinterpret_cast<struct sockaddr*>(&servaddr), &len)) {
        LogPrintf("Stratum bind failed: unsupported address family for %s\n", bind_addr->ToStringAddrPort());
        return false;
    }

    LogPrintf("Stratum creating socket for %s\n", bind_addr->ToStringAddrPort());
    auto socket = CreateSock(bind_addr->GetSAFamily(), SOCK_STREAM, IPPROTO_TCP);
    if (!socket) {
        LogPrintf("Stratum socket creation failed for %s: %s\n", bind_addr->ToStringAddrPort(), NetworkErrorString(WSAGetLastError()));
        return false;
    }
    LogPrintf("Stratum socket created for %s\n", bind_addr->ToStringAddrPort());

    int n_one = 1;
    if (socket->SetSockOpt(SOL_SOCKET, SO_REUSEADDR, (sockopt_arg_type)&n_one, sizeof(int)) == SOCKET_ERROR) {
        LogPrintf("Stratum warning: error setting SO_REUSEADDR on %s: %s\n", bind_addr->ToStringAddrPort(), NetworkErrorString(WSAGetLastError()));
    }

    if (socket->Bind(reinterpret_cast<struct sockaddr*>(&servaddr), len) == SOCKET_ERROR) {
        LogPrintf("Stratum bind failed for %s: %s\n", bind_addr->ToStringAddrPort(), NetworkErrorString(WSAGetLastError()));
        return false;
    }
    LogPrintf("Stratum bind succeeded for %s\n", bind_addr->ToStringAddrPort());

    if (socket->Listen(SOMAXCONN) == SOCKET_ERROR) {
        LogPrintf("Stratum listen failed for %s: %s\n", bind_addr->ToStringAddrPort(), NetworkErrorString(WSAGetLastError()));
        return false;
    }
    LogPrintf("Stratum listen succeeded for %s\n", bind_addr->ToStringAddrPort());

    m_listen_socket = std::move(socket);
    m_listening.store(true);
    return true;
}

bool Server::Start()
{
    if (!m_config.enabled) return true;
    if (m_running.exchange(true)) return true;

    if (!InitListeningSocket()) {
        m_running.store(false);
        m_listening.store(false);
        return false;
    }

    m_job_manager.RefreshJobs(RefreshReason::NEW_PREVHASH);
    m_thread = std::thread(&util::TraceThread, "stratum", [this] { ThreadRun(); });
    LogPrintf("Stratum configured and listening on %s:%u\n", m_config.bind, m_config.port);
    return true;
}

void Server::Interrupt()
{
    m_running.store(false);
}

void Server::Stop()
{
    Interrupt();
    if (m_thread.joinable()) m_thread.join();
    m_listen_socket.reset();
    m_listening.store(false);
}

Session& Server::GetOrCreateSession(uint64_t session_id)
{
    LOCK(m_mutex);
    if (!m_sessions.contains(session_id)) {
        auto s = std::make_unique<Session>();
        s->session_id = session_id;
        s->extranonce2_size = m_config.extranonce2_size;
        s->difficulty = m_config.difficulty;
        s->version_rolling_mask = m_config.version_rolling ? m_config.version_rolling_mask : 0;
        s->extranonce1 = m_job_manager.GetSessionExtranonce1(session_id);
        m_sessions.emplace(session_id, std::move(s));
    }
    return *m_sessions.at(session_id);
}

UniValue Server::HandleMessage(uint64_t session_id, const UniValue& request)
{
    const UniValue id = request.exists("id") ? request["id"] : UniValue{UniValue::VNULL};
    if (!request.isObject() || !request.exists("method")) {
        return BuildError(id, 20, "malformed-request");
    }

    Session& session = GetOrCreateSession(session_id);
    const std::string method = request["method"].get_str();
    const UniValue params = request.exists("params") ? request["params"] : UniValue{UniValue::VARR};

    if (method == "mining.subscribe") {
        session.subscribed = true;

        UniValue subscriptions(UniValue::VARR);
        UniValue s1(UniValue::VARR);
        s1.push_back("mining.set_difficulty");
        s1.push_back("subid-diff");
        subscriptions.push_back(std::move(s1));

        UniValue s2(UniValue::VARR);
        s2.push_back("mining.notify");
        s2.push_back("subid-notify");
        subscriptions.push_back(std::move(s2));

        UniValue result(UniValue::VARR);
        result.push_back(std::move(subscriptions));
        result.push_back(session.extranonce1);
        result.push_back(session.extranonce2_size);

        UniValue resp(UniValue::VOBJ);
        resp.pushKV("id", id);
        resp.pushKV("result", std::move(result));
        resp.pushKV("error", UniValue{UniValue::VNULL});
        return resp;
    }

    if (method == "mining.authorize") {
        if (!params.isArray() || params.size() < 1 || params[0].get_str().empty()) {
            return BuildError(id, 24, "invalid-worker-name");
        }
        session.worker_name = params[0].get_str();
        session.authorized = true;
        return BuildSuccess(id);
    }

    if (method == "mining.suggest_difficulty" || method == "mining.extranonce.subscribe") {
        return BuildSuccess(id);
    }

    if (method == "mining.submit") {
        auto submit = ParseSubmitParams(params);
        if (!submit) return BuildError(id, 20, "invalid-submit-format");

        auto job = m_job_manager.GetJob(submit->job_id);
        if (!job) {
            LOCK(m_mutex);
            m_rejected_shares++;
            session.rejected++;
            return BuildError(id, 21, "job-not-found");
        }

        arith_uint256 pow_limit;
        pow_limit.SetCompact(job->nbits);
        const auto val = ValidateShare(*submit, session, *job, pow_limit);

        LOCK(m_mutex);
        if (!val.accepted_share) {
            m_rejected_shares++;
            session.rejected++;
            return BuildError(id, 23, val.reject_reason);
        }

        m_accepted_shares++;
        session.accepted++;
        return BuildSuccess(id);
    }

    return BuildError(id, 404, "method-not-found");
}

void Server::ThreadRun()
{
    m_accept_loop_running.store(true);
    LogPrintf("Stratum accept loop started on %s:%u\n", m_config.bind, m_config.port);
    auto next_job_refresh = std::chrono::steady_clock::now();

    while (m_running.load()) {
        if (!m_listen_socket) break;

        const auto now = std::chrono::steady_clock::now();
        if (now >= next_job_refresh) {
            m_job_manager.RefreshJobs(RefreshReason::TEMPLATE_UPDATE_ONLY);
            next_job_refresh = now + std::chrono::milliseconds{m_config.job_refresh_ms};
        }

        Sock::Event occurred{0};
        if (!m_listen_socket->Wait(std::chrono::milliseconds{100}, Sock::RECV, &occurred)) {
            LogPrintf("Stratum accept loop wait failed: %s\n", NetworkErrorString(WSAGetLastError()));
            continue;
        }

        if ((occurred & Sock::RECV) != 0) {
            struct sockaddr_storage addr;
            socklen_t len = sizeof(addr);
            auto client = m_listen_socket->Accept(reinterpret_cast<struct sockaddr*>(&addr), &len);
            if (!client) {
                const int err{WSAGetLastError()};
                if (err != WSAEWOULDBLOCK && err != WSAEINTR && err != WSAEAGAIN) {
                    LogPrintf("Stratum accept failed: %s\n", NetworkErrorString(err));
                }
            }
        }
    }

    m_accept_loop_running.store(false);
    LogPrintf("Stratum accept loop exited on %s:%u\n", m_config.bind, m_config.port);
}

Info Server::GetInfo() const
{
    Info info;
    info.enabled = m_config.enabled;
    info.listening = m_listening.load();
    info.accept_loop_running = m_accept_loop_running.load();
    info.bind = m_config.bind;
    info.port = m_config.port;
    info.version_rolling_enabled = m_config.version_rolling;
    info.version_rolling_mask = m_config.version_rolling_mask;

    LOCK(m_mutex);
    info.clients = m_sessions.size();
    info.accepted_shares = m_accepted_shares;
    info.rejected_shares = m_rejected_shares;
    info.blocks_found = m_blocks_found;
    return info;
}

Config GetConfig(const ArgsManager& args, bool is_regtest)
{
    Config cfg;
    cfg.enabled = args.GetBoolArg("-stratum", false);
    cfg.bind = args.GetArg("-stratumbind", "127.0.0.1");
    cfg.port = static_cast<uint16_t>(args.GetIntArg("-stratumport", 3333));
    cfg.extranonce2_size = static_cast<uint32_t>(args.GetIntArg("-stratumextranonce2size", 4));
    cfg.difficulty = args.GetIntArg("-stratumdifficulty", is_regtest ? 1 : 1024);
    cfg.payout_address = args.GetArg("-stratumpayoutaddress", "");
    cfg.version_rolling = args.GetBoolArg("-stratumversionrolling", false);
    cfg.version_rolling_mask = ParseHexU32(args.GetArg("-stratumversionrollingmask", "1fffe000"), 0x1fffe000);
    cfg.job_refresh_ms = args.GetIntArg("-stratumjobrefreshms", 1000);
    cfg.allow_self_select = args.GetBoolArg("-stratumallowselfselect", false);
    return cfg;
}

} // namespace stratum
