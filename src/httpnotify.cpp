// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpnotify.h>

#include <compat/compat.h>
#include <logging.h>
#include <util/sock.h>

#include <charconv>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

static constexpr int HTTP_NOTIFY_TIMEOUT_SECS = 5;

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
    request += "Host: " + host;
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

    // Create TCP socket
    SOCKET sock = socket(ai_result->ai_family, ai_result->ai_socktype, ai_result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        LogWarning("httpnotify: failed to create socket for '%s:%d': %s", host, port, NetworkErrorString(WSAGetLastError()));
        freeaddrinfo(ai_result);
        return;
    }

    // Set SO_SNDTIMEO for connect and send timeout
#ifdef WIN32
    DWORD timeout_ms = HTTP_NOTIFY_TIMEOUT_SECS * 1000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (sockopt_arg_type)&timeout_ms, sizeof(timeout_ms));
#else
    struct timeval timeout;
    timeout.tv_sec = HTTP_NOTIFY_TIMEOUT_SECS;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (sockopt_arg_type)&timeout, sizeof(timeout));
#endif

    // Connect
    if (connect(sock, ai_result->ai_addr, ai_result->ai_addrlen) == SOCKET_ERROR) {
        LogWarning("httpnotify: connection failed to '%s:%d': %s", host, port, NetworkErrorString(WSAGetLastError()));
#ifdef WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        freeaddrinfo(ai_result);
        return;
    }

    freeaddrinfo(ai_result);

    // Build and send HTTP GET request
    std::string request = BuildHttpGetRequest(host, port, path);
    ssize_t sent = send(sock, request.c_str(), request.size(), MSG_NOSIGNAL);
    if (sent == SOCKET_ERROR || static_cast<size_t>(sent) != request.size()) {
        LogWarning("httpnotify: send failed to '%s:%d': %s", host, port, NetworkErrorString(WSAGetLastError()));
    }

    // Close socket
#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}
