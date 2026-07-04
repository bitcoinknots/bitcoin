// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpnotify.h>

#include <compat/compat.h>
#include <logging.h>
#include <netbase.h>
#include <util/sock.h>

#include <charconv>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

std::optional<ParsedUrl> ParseHttpUrl(const std::string& url)
{
    const std::string prefix = "http://";
    if (url.substr(0, prefix.size()) != prefix) {
        LogWarning("httpnotify: URL does not start with http:// scheme: %s", url);
        return std::nullopt;
    }

    std::string remainder = url.substr(prefix.size());

    std::string host;
    uint16_t port = 80;
    std::string path = "/";

    // Handle IPv6 bracket notation: http://[::1]:port/path
    if (!remainder.empty() && remainder[0] == '[') {
        size_t bracket_close = remainder.find(']');
        if (bracket_close == std::string::npos) {
            LogWarning("httpnotify: malformed IPv6 address (missing closing bracket): %s", url);
            return std::nullopt;
        }
        host = remainder.substr(1, bracket_close - 1);
        remainder = remainder.substr(bracket_close + 1);

        // After the closing bracket, expect either ':', '/', or end
        if (!remainder.empty()) {
            if (remainder[0] == ':') {
                remainder = remainder.substr(1);
                // Extract port
                size_t slash_pos = remainder.find('/');
                std::string port_str = remainder.substr(0, slash_pos);
                if (port_str.empty()) {
                    LogWarning("httpnotify: empty port value in URL: %s", url);
                    return std::nullopt;
                }
                uint32_t port_val{0};
                auto [ptr, ec] = std::from_chars(port_str.data(), port_str.data() + port_str.size(), port_val);
                if (ec != std::errc() || ptr != port_str.data() + port_str.size()) {
                    LogWarning("httpnotify: non-numeric port in URL: %s", url);
                    return std::nullopt;
                }
                if (port_val < 1 || port_val > 65535) {
                    LogWarning("httpnotify: port out of range (1-65535) in URL: %s", url);
                    return std::nullopt;
                }
                port = static_cast<uint16_t>(port_val);
                if (slash_pos != std::string::npos) {
                    path = remainder.substr(slash_pos);
                }
            } else if (remainder[0] == '/') {
                path = remainder;
            } else {
                LogWarning("httpnotify: unexpected character after IPv6 address: %s", url);
                return std::nullopt;
            }
        }
    } else {
        // Non-IPv6: extract host, optional port, optional path
        size_t colon_pos = remainder.find(':');
        size_t slash_pos = remainder.find('/');

        if (colon_pos != std::string::npos && (slash_pos == std::string::npos || colon_pos < slash_pos)) {
            // Host:port case
            host = remainder.substr(0, colon_pos);
            std::string after_colon = remainder.substr(colon_pos + 1);
            size_t path_pos = after_colon.find('/');
            std::string port_str = after_colon.substr(0, path_pos);
            if (port_str.empty()) {
                LogWarning("httpnotify: empty port value in URL: %s", url);
                return std::nullopt;
            }
            uint32_t port_val{0};
            auto [ptr, ec] = std::from_chars(port_str.data(), port_str.data() + port_str.size(), port_val);
            if (ec != std::errc() || ptr != port_str.data() + port_str.size()) {
                LogWarning("httpnotify: non-numeric port in URL: %s", url);
                return std::nullopt;
            }
            if (port_val < 1 || port_val > 65535) {
                LogWarning("httpnotify: port out of range (1-65535) in URL: %s", url);
                return std::nullopt;
            }
            port = static_cast<uint16_t>(port_val);
            if (path_pos != std::string::npos) {
                path = after_colon.substr(path_pos);
            }
        } else if (slash_pos != std::string::npos) {
            // Host/path case (no port)
            host = remainder.substr(0, slash_pos);
            path = remainder.substr(slash_pos);
        } else {
            // Host only
            host = remainder;
        }
    }

    if (host.empty()) {
        LogWarning("httpnotify: missing host in URL: %s", url);
        return std::nullopt;
    }

    return ParsedUrl{host, port, path};
}

std::string BuildHttpGetRequest(const std::string& host, uint16_t port, const std::string& path)
{
    std::string request = "GET " + path + " HTTP/1.1\r\n";
    request += "Host: ";
    if (host.find(':') != std::string::npos && host.find(']') == std::string::npos) {
        request += "[" + host + "]";
    } else {
        request += host;
    }
    if (port != 80) {
        request += ":" + std::to_string(port);
    }
    request += "\r\n";
    request += "Connection: close\r\n";
    request += "\r\n";
    return request;
}

void HttpNotify(const std::string& url)
{
    auto parsed = ParseHttpUrl(url);
    if (!parsed) {
        return;
    }

    const std::string& host = parsed->host;
    uint16_t port = parsed->port;
    const std::string& path = parsed->path;

    // DNS resolution
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* ai_result = nullptr;
    std::string port_str = std::to_string(port);
    int gai_err = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &ai_result);
    if (gai_err != 0) {
        LogWarning("httpnotify: DNS resolution failed for host '%s': %s", host, gai_strerror(gai_err));
        return;
    }

    struct AddrInfoDeleter {
        void operator()(addrinfo* p) const { freeaddrinfo(p); }
    };
    std::unique_ptr<addrinfo, AddrInfoDeleter> ai_guard{ai_result};

    // Build HTTP GET request (outside loop — same for all candidates)
    const std::string request = BuildHttpGetRequest(host, port, path);

    // Try each address candidate in order until one connects
    for (addrinfo* ai = ai_result; ai != nullptr; ai = ai->ai_next) {
        // Create a socket for this address family; will be closed on scope exit
        std::unique_ptr<Sock> sock = CreateSock(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (!sock) {
            LogWarning("httpnotify: failed to create socket for '%s:%d'", host, port);
            continue;
        }

        // Use non-blocking connect to enforce timeout via Wait()
        if (!sock->SetNonBlocking()) {
            LogWarning("httpnotify: SetNonBlocking failed for '%s:%d'", host, port);
            continue;
        }

        // Attempt connect
        if (sock->Connect(ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) == SOCKET_ERROR) {
            const int err = WSAGetLastError();
            if (err == WSAEINPROGRESS || err == WSAEWOULDBLOCK || err == WSAEINVAL) {
                // Async connect in progress; wait up to nConnectTimeout ms
                Sock::Event occurred{0};
                if (!sock->Wait(std::chrono::milliseconds{nConnectTimeout}, Sock::RECV | Sock::SEND, &occurred)) {
                    LogWarning("httpnotify: wait for connect failed for '%s:%d'", host, port);
                    continue;
                }
                if (occurred == 0) {
                    LogWarning("httpnotify: connect timed out for '%s:%d'", host, port);
                    continue;
                }
                // Check SO_ERROR to confirm actual connection success
                int sockerr{0};
                socklen_t sockerr_len{sizeof(sockerr)};
                if (sock->GetSockOpt(SOL_SOCKET, SO_ERROR, &sockerr, &sockerr_len) == SOCKET_ERROR) {
                    LogWarning("httpnotify: getsockopt SO_ERROR failed for '%s:%d'", host, port);
                    continue;
                }
                if (sockerr != 0) {
                    LogWarning("httpnotify: connect failed after wait for '%s:%d': %s", host, port, NetworkErrorString(sockerr));
                    continue;
                }
            } else {
#ifdef WIN32
                if (err != WSAEISCONN) {
#endif
                    LogWarning("httpnotify: connect() failed for '%s:%d': %s", host, port, NetworkErrorString(err));
                    continue;
#ifdef WIN32
                }
#endif
            }
        }

        // Connected; send the HTTP GET request
        const ssize_t sent = sock->Send(
            request.data(), request.size(),
#ifndef WIN32
            MSG_NOSIGNAL
#else
            0
#endif
        );
        if (sent < 0 || static_cast<size_t>(sent) != request.size()) {
            LogWarning("httpnotify: send failed for '%s:%d'", host, port);
        }
        return; // Socket closed via RAII, addrinfo freed via ai_guard
    }

    // All address candidates failed
    LogWarning("httpnotify: all candidates failed for '%s:%d'", host, port);
}
