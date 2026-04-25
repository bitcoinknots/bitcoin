// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stratum/server.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <common/args.h>
#include <interfaces/mining.h>
#include <logging.h>
#include <netbase.h>
#include <stratum/share_validation.h>
#include <stratum/stratum_messages.h>
#include <tinyformat.h>
#include <util/sock.h>
#include <util/thread.h>
#include <util/time.h>

#include <chrono>
#include <array>
#include <algorithm>

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

std::optional<CService> ResolveBindAddress(const std::string& bind, uint16_t port)
{
    if (bind == "0.0.0.0") {
        struct sockaddr_in addr4{};
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        addr4.sin_addr.s_addr = htonl(INADDR_ANY);
        CService service(addr4);
        LogPrintf("Stratum ResolveBindAddress path=explicit-ipv4-any bind=%s port=%u service=%s valid=%d bind_any=%d family=%d\n",
                  bind, port, service.ToStringAddrPort(), service.IsValid(), service.IsBindAny(), service.GetSAFamily());
        return service;
    }
    if (bind == "::") {
        struct sockaddr_in6 addr6{};
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        addr6.sin6_addr = in6addr_any;
        CService service(addr6);
        LogPrintf("Stratum ResolveBindAddress path=explicit-ipv6-any bind=%s port=%u service=%s valid=%d bind_any=%d family=%d\n",
                  bind, port, service.ToStringAddrPort(), service.IsValid(), service.IsBindAny(), service.GetSAFamily());
        return service;
    }
    const auto resolved = Lookup(bind, port, /*fAllowLookup=*/false);
    if (resolved.has_value()) {
        LogPrintf("Stratum ResolveBindAddress path=lookup bind=%s port=%u service=%s valid=%d bind_any=%d family=%d\n",
                  bind, port, resolved->ToStringAddrPort(), resolved->IsValid(), resolved->IsBindAny(), resolved->GetSAFamily());
    } else {
        LogPrintf("Stratum ResolveBindAddress path=lookup bind=%s port=%u failed\n", bind, port);
    }
    return resolved;
}

std::string SockAddrToString(const struct sockaddr_storage& addr, socklen_t len)
{
    CService peer;
    if (peer.SetSockAddr(reinterpret_cast<const struct sockaddr*>(&addr), len)) {
        return peer.ToStringAddrPort();
    }
    return "<unknown-peer>";
}

std::string SockAddrToIP(const struct sockaddr_storage& addr, socklen_t len)
{
    CService peer;
    if (peer.SetSockAddr(reinterpret_cast<const struct sockaddr*>(&addr), len)) {
        return peer.ToStringAddr();
    }
    return "<unknown-peer>";
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
    const auto bind_addr = ResolveBindAddress(m_config.bind, m_config.port);
    if (!bind_addr.has_value()) {
        LogPrintf("Stratum bind failed: unable to resolve bind address '%s:%u'\n", m_config.bind, m_config.port);
        return false;
    }
    LogPrintf("Stratum bind resolve result addr=%s valid=%d bind_any=%d family=%d\n",
              bind_addr->ToStringAddrPort(), bind_addr->IsValid(), bind_addr->IsBindAny(), bind_addr->GetSAFamily());
    if (!bind_addr->IsValid() && !bind_addr->IsBindAny()) {
        LogPrintf("Stratum bind failed: resolved address is neither valid nor bind-any '%s:%u'\n", m_config.bind, m_config.port);
        return false;
    }

    struct sockaddr_storage servaddr;
    socklen_t len = sizeof(servaddr);
    if (!bind_addr->GetSockAddr(reinterpret_cast<struct sockaddr*>(&servaddr), &len)) {
        LogPrintf("Stratum bind failed: unsupported address family for %s\n", bind_addr->ToStringAddrPort());
        return false;
    }

    CService final_bind_addr;
    if (!final_bind_addr.SetSockAddr(reinterpret_cast<struct sockaddr*>(&servaddr), len)) {
        LogPrintf("Stratum bind failed: unable to normalize sockaddr for %s\n", bind_addr->ToStringAddrPort());
        return false;
    }
    LogPrintf("Stratum bind sockaddr resolved to %s (family=%d, valid=%d, bind_any=%d)\n",
              final_bind_addr.ToStringAddrPort(), final_bind_addr.GetSAFamily(), final_bind_addr.IsValid(), final_bind_addr.IsBindAny());

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
    if (bind_addr->GetSAFamily() == AF_INET6) {
        int n_zero = 0;
        if (socket->SetSockOpt(IPPROTO_IPV6, IPV6_V6ONLY, (sockopt_arg_type)&n_zero, sizeof(int)) == SOCKET_ERROR) {
            LogPrintf("Stratum warning: error setting IPV6_V6ONLY=0 on %s: %s\n", bind_addr->ToStringAddrPort(), NetworkErrorString(WSAGetLastError()));
        }
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

    {
        LOCK(m_mutex);
        m_start_time = GetTime();
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
    {
        LOCK(m_mutex);
        m_connections.clear();
        m_sessions.clear();
        m_start_time = 0;
    }

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
        LOCK(m_mutex);
        session.worker_name = params[0].get_str();
        session.authorized = true;
        m_last_authorized_worker = session.worker_name;
        return BuildSuccess(id);
    }

    if (method == "mining.suggest_difficulty" || method == "mining.extranonce.subscribe") {
        return BuildSuccess(id);
    }

    if (method == "mining.submit") {
        auto submit = ParseSubmitParams(params);
        if (!submit) {
            LOCK(m_mutex);
            m_last_rejected_share_reason = "invalid-submit-format";
            return BuildError(id, 20, "invalid-submit-format");
        }

        auto job = m_job_manager.GetJob(submit->job_id);
        if (!job) {
            LOCK(m_mutex);
            m_rejected_shares++;
            session.rejected++;
            m_last_rejected_share_reason = "job-not-found";
            return BuildError(id, 21, "job-not-found");
        }

        arith_uint256 pow_limit;
        pow_limit.SetCompact(job->nbits);
        const auto val = ValidateShare(*submit, session, *job, pow_limit);

        LOCK(m_mutex);
        if (!val.accepted_share) {
            m_rejected_shares++;
            session.rejected++;
            m_last_rejected_share_reason = val.reject_reason;
            return BuildError(id, 23, val.reject_reason);
        }

        m_accepted_shares++;
        session.accepted++;
        m_last_accepted_share_hash = val.block_hash.GetHex();
        m_last_block_submission_result = "not-a-block-candidate";

        if (val.accepted_block && job->block_template) {
            try {
                const uint32_t ntime = static_cast<uint32_t>(std::stoul(submit->ntime, nullptr, 16));
                const uint32_t nonce = static_cast<uint32_t>(std::stoul(submit->nonce, nullptr, 16));
                const bool submitted = job->block_template->submitSolution(job->version, ntime, nonce, job->block_template->getCoinbaseTx());
                if (submitted) {
                    m_blocks_found++;
                    m_last_block_submission_result = "accepted";
                    LogPrintf("Stratum block candidate accepted session=%u job_id=%s hash=%s\n", session_id, submit->job_id, val.block_hash.GetHex());
                } else {
                    m_last_block_submission_result = "rejected";
                    LogPrintf("Stratum block candidate rejected session=%u job_id=%s hash=%s\n", session_id, submit->job_id, val.block_hash.GetHex());
                }
            } catch (...) {
                m_last_block_submission_result = "parse-failure";
                LogPrintf("Stratum block candidate parse failure session=%u job_id=%s\n", session_id, submit->job_id);
            }
        }

        return BuildSuccess(id);
    }

    return BuildError(id, 404, "method-not-found");
}

bool Server::SendMessageToClient(const Sock& socket, uint64_t session_id, const UniValue& payload, const char* context) const
{
    const std::string out = payload.write() + "\n";
    size_t sent{0};
    while (sent < out.size()) {
        const ssize_t ret = socket.Send(out.data() + sent, out.size() - sent, MSG_NOSIGNAL);
        if (ret <= 0) {
            LogPrintf("Stratum session=%u send failed (%s): %s\n", session_id, context, NetworkErrorString(WSAGetLastError()));
            return false;
        }
        sent += static_cast<size_t>(ret);
    }
    LogPrintf("Stratum response sent session=%u (%s): %s\n", session_id, context, out);
    return true;
}

std::vector<UniValue> Server::BuildPostAuthorizeMessages(uint64_t session_id)
{
    std::vector<UniValue> out;
    double session_difficulty{0.0};
    {
        LOCK(m_mutex);
        const auto it = m_sessions.find(session_id);
        if (it == m_sessions.end()) return out;
        Session& session = *it->second;
        if (!session.subscribed || !session.authorized || session.initial_messages_sent) {
            return out;
        }
        session.initial_messages_sent = true;
        session_difficulty = session.difficulty;
    }

    UniValue diff_params(UniValue::VARR);
    diff_params.push_back(session_difficulty);
    UniValue diff(UniValue::VOBJ);
    diff.pushKV("id", UniValue{UniValue::VNULL});
    diff.pushKV("method", "mining.set_difficulty");
    diff.pushKV("params", std::move(diff_params));
    out.push_back(std::move(diff));

    if (const auto job = m_job_manager.CreateJobForSession(session_id)) {
        LOCK(m_mutex);
        m_last_notify_time = GetTime();
        out.push_back(m_job_manager.BuildNotify(*job));
    }
    return out;
}

void Server::HandleClient(uint64_t session_id)
{
    std::unique_ptr<Sock> socket;
    {
        LOCK(m_mutex);
        const auto it = m_connections.find(session_id);
        if (it == m_connections.end()) return;
        socket = std::move(it->second->socket);
    }
    if (!socket) return;

    std::string recv_buffer;
    recv_buffer.reserve(4096);
    std::array<char, 4096> buf;

    while (m_running.load()) {
        Sock::Event occurred{0};
        if (!socket->Wait(std::chrono::milliseconds{100}, Sock::RECV, &occurred)) {
            continue;
        }
        if ((occurred & Sock::RECV) == 0) {
            if ((occurred & Sock::ERR) != 0) break;
            continue;
        }

        const ssize_t ret = socket->Recv(buf.data(), buf.size(), 0);
        if (ret <= 0) break;
        recv_buffer.append(buf.data(), static_cast<size_t>(ret));

        size_t pos{0};
        while (true) {
            const size_t end = recv_buffer.find('\n', pos);
            if (end == std::string::npos) {
                recv_buffer.erase(0, pos);
                break;
            }
            std::string line = recv_buffer.substr(pos, end - pos);
            pos = end + 1;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;

            LogPrintf("Stratum request received session=%u: %s\n", session_id, line);

            UniValue request;
            if (!request.read(line)) {
                const UniValue err = BuildError(UniValue{UniValue::VNULL}, 20, "malformed-request");
                if (!SendMessageToClient(*socket, session_id, err, "parse-error")) {
                    goto disconnect;
                }
                continue;
            }

            const UniValue response = HandleMessage(session_id, request);
            if (!SendMessageToClient(*socket, session_id, response, "rpc-response")) {
                goto disconnect;
            }

            for (const UniValue& msg : BuildPostAuthorizeMessages(session_id)) {
                if (!SendMessageToClient(*socket, session_id, msg, "post-authorize")) {
                    goto disconnect;
                }
            }
        }
    }

disconnect:
    {
        LOCK(m_mutex);
        m_connections.erase(session_id);
        m_sessions.erase(session_id);
    }
    LogPrintf("Stratum client disconnected session=%u\n", session_id);
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
                continue;
            }

            const uint64_t session_id = m_next_session_id.fetch_add(1);
            auto connection = std::make_unique<ClientConnection>();
            connection->session_id = session_id;
            connection->peer = SockAddrToString(addr, len);
            const std::string peer = connection->peer;
            const std::string peer_ip = SockAddrToIP(addr, len);
            connection->socket = std::move(client);

            {
                LOCK(m_mutex);
                m_connections.emplace(session_id, std::move(connection));
                m_last_client_ip = peer_ip;
            }

            std::thread(&util::TraceThread, strprintf("stratumcli-%u", session_id), [this, session_id] {
                HandleClient(session_id);
            }).detach();

            GetOrCreateSession(session_id);
            LogPrintf("Stratum client accepted session=%u peer=%s\n", session_id, peer);
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
    info.clients = m_connections.size();
    info.connected_clients = info.clients;
    info.authorized_clients = std::count_if(m_sessions.begin(), m_sessions.end(), [](const auto& entry) {
        return entry.second && entry.second->authorized;
    });
    info.accepted_shares = m_accepted_shares;
    info.rejected_shares = m_rejected_shares;
    info.blocks_found = m_blocks_found;
    info.last_client_ip = m_last_client_ip;
    info.last_authorized_worker = m_last_authorized_worker;
    info.last_accepted_share_hash = m_last_accepted_share_hash;
    info.last_rejected_share_reason = m_last_rejected_share_reason;
    info.last_block_submission_result = m_last_block_submission_result;
    info.last_notify_time = m_last_notify_time;
    if (m_start_time > 0) info.uptime = std::max<int64_t>(0, GetTime() - m_start_time);
    if (const auto current_job = m_job_manager.CurrentJob()) {
        info.current_job_id = current_job->id;
        info.current_height = current_job->height;
        info.current_prevhash = current_job->prevhash.GetHex();
    }
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
