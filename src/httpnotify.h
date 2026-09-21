// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTPNOTIFY_H
#define BITCOIN_HTTPNOTIFY_H

#include <cstdint>
#include <optional>
#include <string>

struct ParsedUrl {
    std::string host; //!< Hostname or IP address (IPv6 without brackets)
    uint16_t port;    //!< TCP port (1–65535; defaults to 80 when omitted from URL)
    std::string path; //!< Request path including leading '/'; defaults to "/"
};

/**
 * Parse an HTTP URL into its host, port, and path components.
 *
 * Accepts only the "http://" scheme. IPv6 addresses must be in
 * bracket notation (e.g. [::1]). Port defaults to 80; path defaults to "/".
 *
 * @param[in] url  The URL string to parse (e.g. "http://localhost:7152/NOTIFY").
 * @return         A populated ParsedUrl on success, or std::nullopt if the URL
 *                 is malformed, uses a non-http scheme, or has an out-of-range port.
 */
std::optional<ParsedUrl> ParseHttpUrl(const std::string& url);

/**
 * Build an HTTP/1.1 GET request string.
 *
 * Produces a minimal request with a request line, Host header (port included
 * only when non-80), Connection: close, and the blank line terminator.
 *
 * @param[in] host  Hostname or IP for the Host header.
 * @param[in] port  TCP port; omitted from the Host header when equal to 80.
 * @param[in] path  Request path (must start with '/').
 * @return          The complete HTTP/1.1 GET request as a std::string.
 */
std::string BuildHttpGetRequest(const std::string& host, uint16_t port, const std::string& path);

/**
 * Perform a fire-and-forget HTTP GET notification to the given URL.
 *
 * Parses the URL, resolves DNS, iterates the addrinfo list attempting a
 * non-blocking connect bounded by nConnectTimeout milliseconds, sends the
 * request on the first successful connection, and closes the socket.
 * All errors are logged at Warning level and silently ignored; no retry.
 *
 * @param[in] url  The target URL (must use the "http://" scheme).
 */
void HttpNotify(const std::string& url);

#endif // BITCOIN_HTTPNOTIFY_H
