// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTPNOTIFY_H
#define BITCOIN_HTTPNOTIFY_H

#include <cstdint>
#include <optional>
#include <string>

struct ParsedUrl {
    std::string host;
    uint16_t port;
    std::string path;
};

/** Parse an http:// URL into host, port, and path components.
 *  Returns std::nullopt if the URL is malformed. */
std::optional<ParsedUrl> ParseHttpUrl(const std::string& url);

/** Build an HTTP/1.1 GET request string for the given host, port, and path. */
std::string BuildHttpGetRequest(const std::string& host, uint16_t port, const std::string& path);

/** Perform a single-shot HTTP GET notification to the given URL.
 *  Parses the URL, connects via raw socket, sends the request, and closes.
 *  All errors are logged and silently ignored (no retry). */
void HttpNotify(const std::string& url);

#endif // BITCOIN_HTTPNOTIFY_H
