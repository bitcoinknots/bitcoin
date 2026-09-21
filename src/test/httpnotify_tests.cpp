// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpnotify.h>
#include <test/util/setup_common.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <chrono>

BOOST_FIXTURE_TEST_SUITE(httpnotify_tests, BasicTestingSetup)

// URL parsing basic cases

BOOST_AUTO_TEST_CASE(parse_url_basic)
{
    // host-only
    auto result = ParseHttpUrl("http://localhost");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(result->host, "localhost");
    BOOST_CHECK_EQUAL(result->port, 80);
    BOOST_CHECK_EQUAL(result->path, "/");

    // host+port
    result = ParseHttpUrl("http://localhost:7152");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(result->host, "localhost");
    BOOST_CHECK_EQUAL(result->port, 7152);
    BOOST_CHECK_EQUAL(result->path, "/");

    // host+path
    result = ParseHttpUrl("http://localhost/NOTIFY");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(result->host, "localhost");
    BOOST_CHECK_EQUAL(result->port, 80);
    BOOST_CHECK_EQUAL(result->path, "/NOTIFY");

    // host+port+path
    result = ParseHttpUrl("http://localhost:7152/NOTIFY");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(result->host, "localhost");
    BOOST_CHECK_EQUAL(result->port, 7152);
    BOOST_CHECK_EQUAL(result->path, "/NOTIFY");
}

BOOST_AUTO_TEST_CASE(parse_url_ipv6)
{
    // IPv6 bracket notation with port and path
    auto result = ParseHttpUrl("http://[::1]:7152/path");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(result->host, "::1");
    BOOST_CHECK_EQUAL(result->port, 7152);
    BOOST_CHECK_EQUAL(result->path, "/path");
}

BOOST_AUTO_TEST_CASE(parse_url_defaults)
{
    // Port defaults to 80 when omitted
    auto result = ParseHttpUrl("http://example.com");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(result->port, 80);

    // Path defaults to "/" when omitted
    result = ParseHttpUrl("http://example.com:8080");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(result->path, "/");

    // Both defaults together
    result = ParseHttpUrl("http://myhost");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(result->port, 80);
    BOOST_CHECK_EQUAL(result->path, "/");
}

BOOST_AUTO_TEST_CASE(parse_url_malformed)
{
    // Missing host
    BOOST_CHECK(!ParseHttpUrl("http://").has_value());

    // Missing host with port
    BOOST_CHECK(!ParseHttpUrl("http://:7152").has_value());

    // Non-numeric port
    BOOST_CHECK(!ParseHttpUrl("http://host:abc").has_value());

    // Port zero (out of range 1-65535)
    BOOST_CHECK(!ParseHttpUrl("http://host:0").has_value());

    // Port out of range (>65535)
    BOOST_CHECK(!ParseHttpUrl("http://host:99999").has_value());

    // Wrong scheme: https
    BOOST_CHECK(!ParseHttpUrl("https://host").has_value());

    // Wrong scheme: ftp
    BOOST_CHECK(!ParseHttpUrl("ftp://host").has_value());
}

// HTTP request construction tests

BOOST_AUTO_TEST_CASE(build_request_format)
{
    // Non-default port: Host header includes port
    std::string req = BuildHttpGetRequest("example.com", 7152, "/NOTIFY");
    BOOST_CHECK_EQUAL(req, "GET /NOTIFY HTTP/1.1\r\nHost: example.com:7152\r\nConnection: close\r\n\r\n");

    // Default port (80): Host header omits port
    req = BuildHttpGetRequest("example.com", 80, "/path");
    BOOST_CHECK_EQUAL(req, "GET /path HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");

    // Root path
    req = BuildHttpGetRequest("localhost", 80, "/");
    BOOST_CHECK_EQUAL(req, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

    // IPv6 literals must be bracketed in the Host header when a port is present
    req = BuildHttpGetRequest("::1", 7152, "/NOTIFY");
    BOOST_CHECK_EQUAL(req, "GET /NOTIFY HTTP/1.1\r\nHost: [::1]:7152\r\nConnection: close\r\n\r\n");
}

// Block hash substitution tests

BOOST_AUTO_TEST_CASE(block_hash_substitution)
{
    const std::string fake_hash{"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"};

    // Single %s in path is replaced with block hash
    {
        std::string url{"http://localhost:7152/%s"};
        util::ReplaceAll(url, "%s", fake_hash);
        auto result = ParseHttpUrl(url);
        BOOST_CHECK(result.has_value());
        BOOST_CHECK_EQUAL(result->path, "/" + fake_hash);
    }

    // Multiple %s occurrences are all replaced
    {
        std::string url{"http://host/%s/confirm/%s"};
        util::ReplaceAll(url, "%s", fake_hash);
        auto result = ParseHttpUrl(url);
        BOOST_CHECK(result.has_value());
        BOOST_CHECK_EQUAL(result->path, "/" + fake_hash + "/confirm/" + fake_hash);
    }

    // No %s leaves URL unchanged
    {
        std::string url{"http://host/static"};
        std::string original{url};
        util::ReplaceAll(url, "%s", fake_hash);
        BOOST_CHECK_EQUAL(url, original);
        auto result = ParseHttpUrl(url);
        BOOST_CHECK(result.has_value());
        BOOST_CHECK_EQUAL(result->path, "/static");
    }
}

// Property test: URL routing correctness

BOOST_AUTO_TEST_CASE(property_1_url_routing_correctness)
{
    // Generate 120+ diverse test vectors: (url_string, should_parse_as_http)
    struct RoutingTestVector {
        std::string url;
        bool should_route_to_http; // true means ParseHttpUrl returns a value
    };

    std::vector<RoutingTestVector> vectors;

    // Valid http:// URLs that SHOULD route to HTTP path (ParseHttpUrl succeeds)
    const std::vector<std::string> valid_hosts = {
        "localhost", "example.com", "192.168.1.1", "10.0.0.1", "mynode.local",
        "a", "host-with-dashes", "sub.domain.example.org", "node1", "router"
    };
    const std::vector<uint16_t> valid_ports = {80, 443, 7152, 8332, 8333, 1, 65535, 9000, 3000, 18332};
    const std::vector<std::string> valid_paths = {"/", "/NOTIFY", "/block", "/api/v1/notify", "/path?key=value",
        "/a/b/c", "/webhook", "/callback", "/new-block", "/update"};

    // Generate 30 valid http:// URLs with host+port+path
    for (size_t i = 0; i < 30; ++i) {
        std::string url = "http://" + valid_hosts[i % valid_hosts.size()] + ":" +
                          std::to_string(valid_ports[i % valid_ports.size()]) +
                          valid_paths[i % valid_paths.size()];
        vectors.push_back({url, true});
    }

    // Generate 10 valid http:// URLs with host only
    for (size_t i = 0; i < 10; ++i) {
        vectors.push_back({"http://" + valid_hosts[i % valid_hosts.size()], true});
    }

    // Generate 10 valid http:// URLs with host+path (default port)
    for (size_t i = 0; i < 10; ++i) {
        vectors.push_back({"http://" + valid_hosts[i % valid_hosts.size()] + valid_paths[i % valid_paths.size()], true});
    }

    // https:// URLs should NOT parse (wrong scheme)
    for (size_t i = 0; i < 15; ++i) {
        std::string url = "https://" + valid_hosts[i % valid_hosts.size()] + ":" +
                          std::to_string(valid_ports[i % valid_ports.size()]) +
                          valid_paths[i % valid_paths.size()];
        vectors.push_back({url, false});
    }

    // HTTP:// (wrong case) should NOT parse
    const std::vector<std::string> wrong_case = {
        "HTTP://localhost", "Http://localhost", "hTTP://host", "HTTP://example.com:80/path",
        "Https://host", "HTTPS://host:443/path", "hTTp://node:7152/NOTIFY",
        "HTTP://a", "HTTP://b:1/c", "HTTP://192.168.1.1:8080/notify"
    };
    for (const auto& url : wrong_case) {
        vectors.push_back({url, false});
    }

    // ftp:// and other schemes should NOT parse
    const std::vector<std::string> other_schemes = {
        "ftp://host/file", "ftp://localhost:21/path", "ssh://host:22",
        "ws://host/socket", "wss://host/socket", "file:///etc/passwd",
        "tcp://host:1234", "udp://host:5678", "mailto:user@host", "telnet://host:23"
    };
    for (const auto& url : other_schemes) {
        vectors.push_back({url, false});
    }

    // Empty and whitespace-only strings should NOT parse
    const std::vector<std::string> empty_whitespace = {
        "", " ", "  ", "\t", "\n", "\r\n", "   ", "\t\t", " \t ", "  \n  "
    };
    for (const auto& url : empty_whitespace) {
        vectors.push_back({url, false});
    }

    // Random text (no scheme) should NOT parse
    const std::vector<std::string> random_text = {
        "localhost", "just-text", "/path/to/thing", "127.0.0.1:8080",
        "echo hello", "curl http://x", "notify.sh", "bitcoin-cli getblock",
        "some random garbage", "!!@@##$$", "http//missing-colon", "http:/missing-slash",
        "ht tp://spaces", "http:localhost", "http/localhost"
    };
    for (const auto& url : random_text) {
        vectors.push_back({url, false});
    }

    // Verify we have at least 100 test vectors
    BOOST_CHECK_GE(vectors.size(), 100U);

    // Run the property check
    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& tv = vectors[i];
        auto result = ParseHttpUrl(tv.url);
        if (tv.should_route_to_http) {
            BOOST_CHECK_MESSAGE(result.has_value(),
                "Expected ParseHttpUrl to succeed for: \"" + tv.url + "\" (vector " + std::to_string(i) + ")");
        } else {
            BOOST_CHECK_MESSAGE(!result.has_value(),
                "Expected ParseHttpUrl to fail for: \"" + tv.url + "\" (vector " + std::to_string(i) + ")");
        }
    }
}

// Property test: block hash substitution completeness

BOOST_AUTO_TEST_CASE(property_2_block_hash_substitution_completeness)
{
    // Generate 64-char hex hashes deterministically using a simple LCG
    auto generate_hex_hash = [](uint32_t seed) -> std::string {
        const char hex_chars[] = "0123456789abcdef";
        std::string hash;
        hash.reserve(64);
        uint32_t state = seed;
        for (int i = 0; i < 64; ++i) {
            state = state * 1103515245 + 12345;
            hash += hex_chars[(state >> 16) & 0xF];
        }
        return hash;
    };

    struct SubstitutionTestVector {
        std::string url_template;
        std::string hash;
        bool has_percent_s;
    };

    std::vector<SubstitutionTestVector> vectors;

    // URL templates WITH %s (substitution should remove all %s)
    const std::vector<std::string> templates_with_s = {
        "http://localhost:7152/%s",
        "http://host/block/%s",
        "http://node:8080/notify?hash=%s",
        "http://example.com/%s/confirm",
        "http://host/%s/%s",
        "http://host/%s/%s/%s",
        "http://10.0.0.1:3000/api/%s",
        "http://miner.local/new/%s/data",
        "http://a/%s",
        "http://pool.example:9000/block?h=%s&confirm=1",
    };

    // URL templates WITHOUT %s (should remain unchanged)
    const std::vector<std::string> templates_without_s = {
        "http://localhost:7152/NOTIFY",
        "http://host/static/path",
        "http://node:8080/webhook",
        "http://example.com/callback",
        "http://host/api/v1/blocks",
        "http://10.0.0.1:3000/ping",
        "http://miner.local/health",
        "http://a/b/c/d",
        "http://pool.example:9000/status",
        "http://router:8332/notify",
    };

    // Generate vectors with %s templates and diverse hashes
    for (size_t i = 0; i < 60; ++i) {
        std::string hash = generate_hex_hash(static_cast<uint32_t>(i * 7 + 42));
        vectors.push_back({
            templates_with_s[i % templates_with_s.size()],
            hash,
            true
        });
    }

    // Generate vectors without %s templates
    for (size_t i = 0; i < 50; ++i) {
        std::string hash = generate_hex_hash(static_cast<uint32_t>(i * 13 + 99));
        vectors.push_back({
            templates_without_s[i % templates_without_s.size()],
            hash,
            false
        });
    }

    // Verify we have at least 100 test vectors
    BOOST_CHECK_GE(vectors.size(), 100U);

    // Run the property check
    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& tv = vectors[i];
        std::string result = tv.url_template;
        util::ReplaceAll(result, "%s", tv.hash);

        if (tv.has_percent_s) {
            // Property (a): no %s remains after substitution
            BOOST_CHECK_MESSAGE(result.find("%s") == std::string::npos,
                "Expected no %%s to remain after substitution in: \"" + tv.url_template +
                "\" with hash: " + tv.hash + " (vector " + std::to_string(i) + ")");
        } else {
            // Property (b): result is identical to original when no %s present
            BOOST_CHECK_MESSAGE(result == tv.url_template,
                "Expected URL unchanged when no %%s present: \"" + tv.url_template +
                "\" (vector " + std::to_string(i) + ")");
        }
    }
}

// Property test: URL parsing round-trip

BOOST_AUTO_TEST_CASE(property_3_url_parsing_round_trip)
{
    struct RoundTripTestVector {
        std::string host;
        uint16_t port;
        std::string path;
    };

    std::vector<RoundTripTestVector> vectors;

    const std::vector<std::string> hosts = {
        "localhost", "example.com", "myhost", "node1", "192.168.1.1",
        "10.0.0.1", "pool.mining.org", "a", "server-01", "data.internal",
        "box", "relay", "upstream", "gw", "monitor"
    };

    const std::vector<uint16_t> ports = {
        80, 7152, 8332, 8333, 443, 1, 1000, 3000, 5000, 8080,
        9090, 18332, 28332, 65535, 4444, 5555, 6666, 7777, 8888, 9999
    };

    const std::vector<std::string> paths = {
        "/", "/NOTIFY", "/block", "/api/v1/notify", "/path",
        "/a/b/c", "/webhook", "/callback", "/new-block", "/update",
        "/status", "/health", "/api/blocks", "/notify/new", "/events"
    };

    // Generate 120 combinations
    for (size_t i = 0; i < 120; ++i) {
        vectors.push_back({
            hosts[i % hosts.size()],
            ports[i % ports.size()],
            paths[i % paths.size()]
        });
    }

    // Verify we have at least 100 test vectors
    BOOST_CHECK_GE(vectors.size(), 100U);

    // Run the property check
    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& tv = vectors[i];

        // Construct URL from components
        std::string url = "http://" + tv.host;
        if (tv.port != 80) {
            url += ":" + std::to_string(tv.port);
        }
        url += tv.path;

        // Parse the constructed URL
        auto result = ParseHttpUrl(url);
        BOOST_CHECK_MESSAGE(result.has_value(),
            "Expected ParseHttpUrl to succeed for constructed URL: \"" + url +
            "\" (vector " + std::to_string(i) + ")");

        if (result.has_value()) {
            // Round-trip property: parsed components match original
            BOOST_CHECK_MESSAGE(result->host == tv.host,
                "Host mismatch for \"" + url + "\": expected \"" + tv.host +
                "\", got \"" + result->host + "\" (vector " + std::to_string(i) + ")");
            BOOST_CHECK_MESSAGE(result->port == tv.port,
                "Port mismatch for \"" + url + "\": expected " + std::to_string(tv.port) +
                ", got " + std::to_string(result->port) + " (vector " + std::to_string(i) + ")");
            BOOST_CHECK_MESSAGE(result->path == tv.path,
                "Path mismatch for \"" + url + "\": expected \"" + tv.path +
                "\", got \"" + result->path + "\" (vector " + std::to_string(i) + ")");
        }
    }
}

// Property test: HTTP request format invariants

BOOST_AUTO_TEST_CASE(property_4_http_request_format_invariants)
{
    struct RequestTestVector {
        std::string host;
        uint16_t port;
        std::string path;
    };

    std::vector<RequestTestVector> vectors;

    const std::vector<std::string> hosts = {
        "localhost", "example.com", "192.168.1.1", "mynode", "pool.mining.org",
        "a", "relay-01", "10.0.0.1", "gateway.local", "backend",
        "node", "server", "monitor", "upstream", "data.internal"
    };

    const std::vector<uint16_t> ports = {
        80, 7152, 8332, 8333, 443, 1, 1000, 3000, 5000, 8080,
        9090, 18332, 28332, 65535, 4444, 5555, 6666, 7777, 8888, 9999
    };

    const std::vector<std::string> paths = {
        "/", "/NOTIFY", "/block", "/api/v1/notify", "/path?key=value",
        "/a/b/c", "/webhook", "/callback", "/new-block", "/update",
        "/status", "/health", "/api/blocks/latest", "/notify/new", "/events/stream"
    };

    // Generate 120 combinations
    for (size_t i = 0; i < 120; ++i) {
        vectors.push_back({
            hosts[i % hosts.size()],
            ports[i % ports.size()],
            paths[i % paths.size()]
        });
    }

    // Verify we have at least 100 test vectors
    BOOST_CHECK_GE(vectors.size(), 100U);

    // Run the property check
    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& tv = vectors[i];
        std::string request = BuildHttpGetRequest(tv.host, tv.port, tv.path);

        // Invariant (a): starts with "GET <path> HTTP/1.1\r\n"
        std::string expected_request_line = "GET " + tv.path + " HTTP/1.1\r\n";
        BOOST_CHECK_MESSAGE(request.substr(0, expected_request_line.size()) == expected_request_line,
            "Request does not start with correct request line for vector " + std::to_string(i) +
            ": expected \"" + expected_request_line + "\" prefix");

        // Invariant (b): contains correct Host header
        std::string expected_host_header = "Host: " + tv.host;
        if (tv.port != 80) {
            expected_host_header += ":" + std::to_string(tv.port);
        }
        expected_host_header += "\r\n";
        BOOST_CHECK_MESSAGE(request.find(expected_host_header) != std::string::npos,
            "Request missing correct Host header for vector " + std::to_string(i) +
            ": expected \"" + expected_host_header + "\"");

        // Invariant (c): contains "Connection: close\r\n"
        BOOST_CHECK_MESSAGE(request.find("Connection: close\r\n") != std::string::npos,
            "Request missing 'Connection: close' header for vector " + std::to_string(i));

        // Invariant (d): ends with "\r\n\r\n"
        BOOST_CHECK_MESSAGE(request.size() >= 4 && request.substr(request.size() - 4) == "\r\n\r\n",
            "Request does not end with \\r\\n\\r\\n for vector " + std::to_string(i));
    }
}

// Property test: malformed URL rejection

BOOST_AUTO_TEST_CASE(property_5_malformed_url_rejection)
{
    std::vector<std::string> malformed_urls;

    // Missing host (empty after scheme)
    const std::vector<std::string> missing_host = {
        "http://", "http://:8080", "http://:8080/path", "http://:1/x",
        "http://:65535", "http://:100/a/b", "http://:7152/NOTIFY",
        "http://:443", "http://:9999/webhook", "http://:1234/block"
    };
    for (const auto& url : missing_host) {
        malformed_urls.push_back(url);
    }

    // Non-numeric port
    const std::vector<std::string> non_numeric_port = {
        "http://host:abc", "http://host:abc/path", "http://localhost:xyz",
        "http://host:12ab", "http://host:ab12", "http://host:port",
        "http://host:!!", "http://host:0x50", "http://host:eighty",
        "http://host:--", "http://host:1.5", "http://host:8080a",
        "http://example.com:NaN/notify", "http://node:undefined", "http://host: 80"
    };
    for (const auto& url : non_numeric_port) {
        malformed_urls.push_back(url);
    }

    // Port zero (out of range)
    const std::vector<std::string> port_zero = {
        "http://host:0", "http://host:0/path", "http://localhost:0/NOTIFY",
        "http://example.com:0", "http://node:0/api", "http://a:0/b",
        "http://server:0/webhook", "http://gw:0/callback",
        "http://192.168.1.1:0/status", "http://monitor:0/health"
    };
    for (const auto& url : port_zero) {
        malformed_urls.push_back(url);
    }

    // Port > 65535
    const std::vector<std::string> port_too_large = {
        "http://host:65536", "http://host:65536/path", "http://host:99999",
        "http://host:100000/api", "http://host:70000", "http://localhost:65537/NOTIFY",
        "http://example.com:99999/block", "http://node:1000000",
        "http://host:999999/webhook", "http://host:65536/callback"
    };
    for (const auto& url : port_too_large) {
        malformed_urls.push_back(url);
    }

    // Wrong scheme: ftp://
    const std::vector<std::string> ftp_scheme = {
        "ftp://host", "ftp://host/path", "ftp://host:21/file",
        "ftp://localhost:21", "ftp://example.com/data",
        "ftp://192.168.1.1:21/pub", "ftp://server/upload",
        "ftp://a:21/b", "ftp://node:2121/files", "ftp://relay/get"
    };
    for (const auto& url : ftp_scheme) {
        malformed_urls.push_back(url);
    }

    // Wrong scheme: https://
    const std::vector<std::string> https_scheme = {
        "https://host", "https://host:443/path", "https://localhost/api",
        "https://example.com:8443/notify", "https://node/block",
        "https://192.168.1.1:443/webhook", "https://server:443",
        "https://a/b", "https://gateway:8443/callback", "https://monitor/health"
    };
    for (const auto& url : https_scheme) {
        malformed_urls.push_back(url);
    }

    // Other malformed patterns
    const std::vector<std::string> other_malformed = {
        "HTTP://host", "Http://host/path", "hTTP://host:80",
        "", " ", "not-a-url", "just-text",
        "http//missing-colon", "http:/single-slash", "://no-scheme",
        "http:", "http:/", "httpX://host", "xhttp://host", "http ://host",
        "ws://host/socket", "wss://host:443/ws", "file:///etc/passwd",
        "tcp://host:1234", "udp://host:5678", "mailto:user@host",
        "telnet://host:23", "ssh://host:22/path", "git://host/repo",
        "hTTPs://host:443", "HTTP://HOST:80/PATH", "HtTp://Mixed:8080/case",
        "http ://space-before-colon", "\thttp://tab-prefix", "http:///empty-host",
        " http://space-prefix", "http://host:65536/overflow",
        "http://host:-1/negative", "http://host:+80/plus", "http://host: /space-port",
        "http://[/bad-ipv6", "http://[::1/unclosed-bracket"
    };
    for (const auto& url : other_malformed) {
        malformed_urls.push_back(url);
    }

    // Verify we have at least 100 test vectors
    BOOST_CHECK_GE(malformed_urls.size(), 100U);

    // Run the property check: ALL must return nullopt
    for (size_t i = 0; i < malformed_urls.size(); ++i) {
        auto result = ParseHttpUrl(malformed_urls[i]);
        BOOST_CHECK_MESSAGE(!result.has_value(),
            "Expected ParseHttpUrl to return nullopt for malformed URL: \"" + malformed_urls[i] +
            "\" (vector " + std::to_string(i) + ")");
    }
}

// Socket-level test: loopback listener validates connect/send/addrinfo path

BOOST_AUTO_TEST_CASE(httpnotify_loopback)
{
#ifdef WIN32
    WSADATA wsa_data;
    (void)WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif

    // 1. Create a TCP listener on 127.0.0.1:0 (OS picks port)
    int listener = (int)socket(AF_INET, SOCK_STREAM, 0);
    BOOST_REQUIRE(listener != -1);

    // SO_REUSEADDR prevents TIME_WAIT failures on rapid re-runs
    int reuse = 1;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
    addr.sin_port        = 0;                       // OS picks port

    BOOST_REQUIRE(bind(listener,
                       reinterpret_cast<struct sockaddr*>(&addr),
                       sizeof(addr)) == 0);
    BOOST_REQUIRE(listen(listener, 1) == 0);

    // 2. Retrieve the OS-assigned port
    struct sockaddr_in bound_addr{};
    socklen_t bound_len = sizeof(bound_addr);
    BOOST_REQUIRE(getsockname(listener,
                              reinterpret_cast<struct sockaddr*>(&bound_addr),
                              &bound_len) == 0);
    const uint16_t bound_port = ntohs(bound_addr.sin_port);

    // 3. Build the expected request bytes (source of truth)
    const std::string expected = BuildHttpGetRequest("127.0.0.1", bound_port, "/NOTIFY");

    // 4. Call HttpNotify() — connects to the listener, sends request, returns
    //    (HttpNotify() does not wait for a response, so it returns before accept())
    const std::string url = "http://127.0.0.1:" + std::to_string(bound_port) + "/NOTIFY";
    HttpNotify(url);

    // 5. Accept the incoming connection with a bounded timeout
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(listener, &readfds);
    timeval timeout{};
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    const int ready = select((int)listener + 1, &readfds, nullptr, nullptr, &timeout);
    BOOST_REQUIRE_MESSAGE(ready > 0, "Timed out waiting for incoming connection");
    int client = (int)accept(listener,
                             reinterpret_cast<struct sockaddr*>(&client_addr),
                             &client_len);
    BOOST_REQUIRE(client != -1);

    // 6. Read exactly len(expected) bytes with a bounded timeout
    std::string received;
    received.resize(expected.size());
    size_t total = 0;
    while (total < expected.size()) {
        FD_ZERO(&readfds);
        FD_SET(client, &readfds);
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        const int recv_ready = select((int)client + 1, &readfds, nullptr, nullptr, &timeout);
        BOOST_REQUIRE_MESSAGE(recv_ready > 0, "Timed out waiting for HTTP notify data");
        int n = (int)recv(client,
                          &received[total],
                          (int)(expected.size() - total),
                          0);
        if (n <= 0) break;
        total += (size_t)n;
    }
    received.resize(total);

    // 7. Cleanup
#ifdef WIN32
    closesocket(client);
    closesocket(listener);
#else
    close(client);
    close(listener);
#endif

    // 8. Assert: received bytes are byte-for-byte equal to BuildHttpGetRequest() output
    BOOST_CHECK_EQUAL(received, expected);
}

// Socket-level test: connection refused validates timeout behavior

BOOST_AUTO_TEST_CASE(httpnotify_connection_refused)
{
#ifdef WIN32
    WSADATA wsa_data;
    (void)WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif

    // 1. Bind on 127.0.0.1:0 to get a free port assigned by the OS, then close
    //    immediately so the port is closed when HttpNotify() tries to connect.
    int probe = (int)socket(AF_INET, SOCK_STREAM, 0);
    BOOST_REQUIRE(probe != -1);

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;

    BOOST_REQUIRE(bind(probe,
                       reinterpret_cast<struct sockaddr*>(&addr),
                       sizeof(addr)) == 0);

    struct sockaddr_in bound_addr{};
    socklen_t bound_len = sizeof(bound_addr);
    BOOST_REQUIRE(getsockname(probe,
                              reinterpret_cast<struct sockaddr*>(&bound_addr),
                              &bound_len) == 0);
    const uint16_t free_port = ntohs(bound_addr.sin_port);

#ifdef WIN32
    closesocket(probe);
#else
    close(probe);
#endif
    // Port is now closed; any connect attempt will get ECONNREFUSED immediately

    // 2. Record wall-clock time before calling HttpNotify()
    const auto t_start = std::chrono::steady_clock::now();

    // 3. Call HttpNotify() — should encounter ECONNREFUSED and return quickly
    const std::string url = "http://127.0.0.1:" + std::to_string(free_port) + "/NOTIFY";
    HttpNotify(url);

    // 4. Compute elapsed wall-clock time
    const auto elapsed = std::chrono::steady_clock::now() - t_start;

    // 5. Assert: must have returned within 5 seconds
    //    ECONNREFUSED on loopback is typically < 1 ms; 5 s is a very conservative bound.
    BOOST_CHECK(elapsed < std::chrono::seconds(5));
}

BOOST_AUTO_TEST_SUITE_END()
