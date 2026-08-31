// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.
#include <mining/datum_bridge.h>

#include <bitcoin-build-config.h>
#include <addresstype.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/netif.h>
#include <common/pcp.h>
#include <key_io.h>
#include <logging.h>
#include <netbase.h>
#include <node/context.h>
#include <random.h>
#include <rpc/request.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/thread.h>
#include <util/threadinterrupt.h>
#include <util/translation.h>
#include <validationinterface.h>

#ifdef USE_UPNP
#include <cstddef> // Work around missing include in miniupnpc 2.3.3.
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
static_assert(MINIUPNPC_API_VERSION >= 17, "miniUPnPc API version >= 17 assumed");
#endif // USE_UPNP

extern "C" {
#include <datum_embedded.h>
#include <datum_logger.h>
}

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace mining {
namespace {

constexpr int64_t DEFAULT_DATUM_PORT{23334};
constexpr int64_t DEFAULT_DATUM_MAX_CLIENTS{32};
constexpr int64_t DEFAULT_DATUM_MAX_PER_IP{4};
constexpr int64_t DEFAULT_DATUM_DIFFICULTY{65536};
constexpr int64_t DEFAULT_DATUM_AUTH_TIMEOUT{10};
constexpr int MAX_DATUM_DIFFICULTY{2147483647};
constexpr bool DEFAULT_DATUM_AUTH{false};
constexpr bool DEFAULT_DATUM_UPNP{false};

struct DatumRuntimeState {
    bool enabled{false};
    std::string listen{"127.0.0.1"};
    uint16_t port{DEFAULT_DATUM_PORT};
    uint64_t share_difficulty{DEFAULT_DATUM_DIFFICULTY};
    bool upnp{DEFAULT_DATUM_UPNP};
    bool auth_required{DEFAULT_DATUM_AUTH};
    std::string payout_address;
    std::string coinbase_tag;
    node::NodeContext* node{nullptr};
};

DatumRuntimeState g_datum_state;
std::mutex g_datum_state_mutex;

struct DatumMappingState {
    bool requested{false};
    bool active{false};
    std::string protocol;
    std::string external;
    uint32_t lifetime{0};
    uint64_t updated_ms{0};
    std::string error;
};

DatumMappingState g_datum_mapping;
std::mutex g_datum_mapping_mutex;

uint64_t NowMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void SetDatumMapping(bool active, std::string protocol = {}, std::string external = {}, uint32_t lifetime = 0, std::string error = {})
{
    std::lock_guard lock{g_datum_mapping_mutex};
    g_datum_mapping.active = active;
    g_datum_mapping.protocol = std::move(protocol);
    g_datum_mapping.external = std::move(external);
    g_datum_mapping.lifetime = lifetime;
    g_datum_mapping.updated_ms = NowMillis();
    g_datum_mapping.error = std::move(error);
}

class DatumValidationInterface final : public CValidationInterface
{
    void UpdatedBlockTip(const CBlockIndex* new_tip, const CBlockIndex* fork_tip, bool initial_download) override
    {
        if (!initial_download && new_tip && new_tip != fork_tip) datum_request_template_refresh();
    }
};

std::unique_ptr<DatumValidationInterface> g_datum_validation;

#ifdef USE_UPNP
using namespace std::chrono_literals;
static constexpr auto DATUM_UPNP_REANNOUNCE_PERIOD{20min};
static constexpr auto DATUM_UPNP_RETRY_PERIOD{5min};
static CThreadInterrupt g_datum_upnp_interrupt;
static std::thread g_datum_upnp_thread;

const char* DatumMappingErrorName(const MappingError error)
{
    switch (error) {
    case MappingError::NETWORK_ERROR: return "network error";
    case MappingError::PROTOCOL_ERROR: return "protocol error";
    case MappingError::UNSUPP_VERSION: return "unsupported protocol";
    case MappingError::NO_RESOURCES: return "no resources";
    }
    return "unknown error";
}

std::optional<MappingResult> ProcessDatumPcpOrNatpmp(const uint16_t port, const uint32_t lifetime, PCPMappingNonce& nonce)
{
    const auto gateway{QueryDefaultGateway(NET_IPV4)};
    if (!gateway) {
        SetDatumMapping(false, {}, {}, 0, "could not determine the IPv4 default gateway");
        LogPrintf("[datum] PCP/NAT-PMP could not determine the IPv4 default gateway\n");
        return std::nullopt;
    }

    const auto bind_address{LookupHost("0.0.0.0", /*fAllowLookup=*/false)};
    if (!bind_address) {
        SetDatumMapping(false, {}, {}, 0, "could not prepare the IPv4 bind address");
        LogPrintf("[datum] PCP/NAT-PMP could not prepare the IPv4 bind address\n");
        return std::nullopt;
    }

    auto result{PCPRequestPortMap(nonce, *gateway, *bind_address, port, lifetime, g_datum_upnp_interrupt)};
    if (const auto* error = std::get_if<MappingError>(&result); error && *error == MappingError::UNSUPP_VERSION) {
        LogPrintf("[datum] PCP is unsupported; falling back to NAT-PMP\n");
        result = NATPMPRequestPortMap(*gateway, port, lifetime, g_datum_upnp_interrupt);
    }
    if (const auto* mapping = std::get_if<MappingResult>(&result)) return *mapping;

    if (const auto* error = std::get_if<MappingError>(&result)) {
        SetDatumMapping(false, {}, {}, 0, DatumMappingErrorName(*error));
        LogPrintf("[datum] PCP/NAT-PMP mapping failed: %s (%d)\n", DatumMappingErrorName(*error), static_cast<int>(*error));
    }
    return std::nullopt;
}

bool ProcessDatumPcpOrNatpmpLoop(const uint16_t port)
{
    PCPMappingNonce nonce;
    GetRandBytes(nonce);
    const uint32_t requested_lifetime{static_cast<uint32_t>(std::chrono::seconds(DATUM_UPNP_REANNOUNCE_PERIOD * 2).count())};

    while (!g_datum_upnp_interrupt) {
        const auto mapping{ProcessDatumPcpOrNatpmp(port, requested_lifetime, nonce)};
        if (!mapping) return false;

        LogPrintf("[datum] mapped Stratum TCP port via %s: %s\n",
                  mapping->version == 0 ? "NAT-PMP" : "PCP", mapping->ToString());
        SetDatumMapping(true, mapping->version == 0 ? "NAT-PMP" : "PCP",
                        mapping->external.ToStringAddrPort(), mapping->lifetime);
        if (mapping->lifetime < 30) {
            LogPrintf("[datum] PCP/NAT-PMP returned an impossibly short mapping lifetime of %u seconds\n", mapping->lifetime);
            return false;
        }

        const std::chrono::seconds sleep_time{std::max<uint32_t>(mapping->lifetime / 2, 1U)};
        if (!g_datum_upnp_interrupt.sleep_for(sleep_time)) return true;
    }
    return true;
}

bool ProcessDatumUpnp(const uint16_t port)
{
    if (g_datum_upnp_interrupt) return false;

    const std::string port_string{strprintf("%u", port)};
    int error{0};
    UPNPDev* devlist{upnpDiscover(2000, nullptr, nullptr, 0, 0, 2, &error)};
    if (!devlist) {
        SetDatumMapping(false, "UPnP", {}, 0, strprintf("discovery found no devices (error %d)", error));
        LogPrintf("[datum] UPnP discovery found no devices (error %d)\n", error);
        return false;
    }

    UPNPUrls urls{};
    IGDdatas data{};
    char lanaddr[64]{};
#if MINIUPNPC_API_VERSION <= 17
    const int valid_igd{UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr))};
#else
    const int valid_igd{UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr), nullptr, 0)};
#endif
    if (valid_igd != 1) {
        SetDatumMapping(false, "UPnP", {}, 0, "no valid IGD found");
        LogPrintf("[datum] no valid UPnP IGD found\n");
        freeUPNPDevlist(devlist);
        if (valid_igd != 0) FreeUPNPUrls(&urls);
        return false;
    }

    bool mapped{false};
    do {
        if (g_datum_upnp_interrupt) break;
        const int result{UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                              port_string.c_str(), port_string.c_str(), lanaddr,
                                              CLIENT_NAME " DATUM Stratum", "TCP", nullptr, "0")};
        if (result != UPNPCOMMAND_SUCCESS) {
            SetDatumMapping(false, "UPnP", {}, 0, strupnperror(result));
            LogPrintf("[datum] UPnP AddPortMapping(%s, %s, %s) failed with code %d (%s)\n",
                      port_string, port_string, lanaddr, result, strupnperror(result));
            break;
        }
        mapped = true;
        char external_ip[64]{};
        const int external_result{UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, external_ip)};
        const std::string external{external_result == UPNPCOMMAND_SUCCESS && external_ip[0]
            ? strprintf("%s:%u", external_ip, port)
            : strprintf("port %u", port)};
        SetDatumMapping(true, "UPnP", external, 0,
                        external_result == UPNPCOMMAND_SUCCESS ? "" : "mapped, but external address query failed");
        LogPrintf("[datum] UPnP mapped Stratum TCP port %s\n", port_string);
    } while (g_datum_upnp_interrupt.sleep_for(DATUM_UPNP_REANNOUNCE_PERIOD));

    if (mapped) {
        const int result{UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port_string.c_str(), "TCP", nullptr)};
        LogPrintf("[datum] UPnP DeletePortMapping(%s) returned %d\n", port_string, result);
    }
    freeUPNPDevlist(devlist);
    FreeUPNPUrls(&urls);
    return mapped;
}

void ThreadDatumUpnp(const uint16_t port)
{
    while (!g_datum_upnp_interrupt) {
        if (!ProcessDatumUpnp(port)) {
            // The node's default port mapping may use NAT-PMP/PCP even when
            // miniupnpc cannot discover an IGD. Try the same protocols for
            // DATUM before waiting for the next discovery cycle.
            if (ProcessDatumPcpOrNatpmpLoop(port)) break;
        }
        if (!g_datum_upnp_interrupt.sleep_for(DATUM_UPNP_RETRY_PERIOD)) break;
    }
}

void StartDatumUpnp(const uint16_t port)
{
    if (g_datum_upnp_thread.joinable()) return;
    {
        std::lock_guard lock{g_datum_mapping_mutex};
        g_datum_mapping = {};
        g_datum_mapping.requested = true;
        g_datum_mapping.updated_ms = NowMillis();
    }
    g_datum_upnp_interrupt.reset();
    g_datum_upnp_thread = std::thread(&util::TraceThread, "datum-upnp", [port] { ThreadDatumUpnp(port); });
}

void StopDatumUpnp()
{
    g_datum_upnp_interrupt();
    if (g_datum_upnp_thread.joinable()) g_datum_upnp_thread.join();
    g_datum_upnp_interrupt.reset();
    std::lock_guard lock{g_datum_mapping_mutex};
    g_datum_mapping = {};
    g_datum_mapping.updated_ms = NowMillis();
}
#else
void StartDatumUpnp(uint16_t)
{
    std::lock_guard lock{g_datum_mapping_mutex};
    g_datum_mapping.requested = true;
    g_datum_mapping.error = "UPnP support is not compiled in";
    g_datum_mapping.updated_ms = NowMillis();
}
void StopDatumUpnp()
{
    std::lock_guard lock{g_datum_mapping_mutex};
    g_datum_mapping = {};
    g_datum_mapping.updated_ms = NowMillis();
}
#endif // USE_UPNP

bool IsLoopbackRpcUrl(const std::string& url)
{
    constexpr std::string_view prefix{"http://"};
    if (!url.starts_with(prefix)) return false;
    std::string authority{url.substr(prefix.size())};
    if (authority.ends_with('/')) authority.pop_back();
    if (authority.find_first_of("/?#@") != std::string::npos) return false;
    uint16_t port{0};
    std::string host;
    return SplitHostPort(authority, port, host) && port != 0 &&
        (host == "127.0.0.1" || host == "::1");
}

bool GetCredentialPair(const ArgsManager& args, std::string& user, std::string& password, bilingual_str& error)
{
    const bool datum_user_set{args.IsArgSet("-datumrpcuser")};
    const bool datum_password_set{args.IsArgSet("-datumrpcpassword")};
    if (datum_user_set != datum_password_set) {
        error = Untranslated("-datumrpcuser and -datumrpcpassword must be configured together");
        return false;
    }
    if (datum_user_set) {
        user = args.GetArg("-datumrpcuser", "");
        password = args.GetArg("-datumrpcpassword", "");
        if (user.empty() || password.empty()) {
            error = Untranslated("DATUM RPC credentials must not be empty");
            return false;
        }
        return true;
    }

    const bool rpc_user_set{args.IsArgSet("-rpcuser")};
    const bool rpc_password_set{args.IsArgSet("-rpcpassword")};
    if (rpc_user_set != rpc_password_set) {
        error = Untranslated("-rpcuser and -rpcpassword must both be set for DATUM fallback");
        return false;
    }
    if (rpc_user_set) {
        user = args.GetArg("-rpcuser", "");
        password = args.GetArg("-rpcpassword", "");
        if (user.empty() || password.empty()) {
            error = Untranslated("RPC fallback credentials for DATUM must not be empty");
            return false;
        }
        return true;
    }

    std::string cookie;
    if (!GetAuthCookie(&cookie)) {
        error = Untranslated("DATUM requires explicit RPC credentials or a readable RPC cookie");
        return false;
    }
    const auto separator{cookie.find(':')};
    if (separator == std::string::npos || separator == 0 || separator + 1 == cookie.size()) {
        error = Untranslated("DATUM could not parse the RPC authentication cookie");
        return false;
    }
    user = cookie.substr(0, separator);
    password = cookie.substr(separator + 1);
    return true;
}

} // namespace

void SetupDatumArgs(ArgsManager& argsman)
{
    argsman.AddArg("-datum", "Enable embedded DATUM/Stratum solo mining (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datumlisten=<addr>", "Address for embedded Stratum V1 to listen on (default: 127.0.0.1)", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datumport=<port>", "Port for embedded Stratum V1 (default: 23334)", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datumupnp", "Use UPnP to map the DATUM Stratum port, with PCP/NAT-PMP fallback (default: 0)", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datumauth", "Require shared Stratum authentication (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datumuser=<user>", "Stratum username; user.worker suffixes are accepted", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datumpassword=<password>", "Stratum shared password", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datummaxclients=<n>", "Maximum embedded Stratum clients (default: 32)", ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datummaxperip=<n>", "Maximum embedded Stratum clients per IP (default: 4)", ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datumaddress=<address>", "Fixed operator-controlled Purity payout address", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datumdiff=<n>", "Fixed Stratum share difficulty (default: 65536)", ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datumcoinbasetag=<tag>", "Embedded DATUM coinbase tag (default: Bitcoin Purity)", ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-datumrpcuser=<user>", "Username for embedded DATUM localhost RPC", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::RPC);
    argsman.AddArg("-datumrpcpassword=<password>", "Password for embedded DATUM localhost RPC", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::RPC);
    argsman.AddArg("-datumrpcurl=<url>", "Advanced loopback HTTP RPC URL override", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::RPC);
}

bool ValidateDatumOptions(const ArgsManager& args, bilingual_str& error)
{
    if (!args.GetBoolArg("-datum", false)) return true;
    if (!args.GetBoolArg("-server", false)) {
        error = Untranslated("-datum=1 requires -server=1 for localhost GBT/submitblock RPC");
        return false;
    }
    const int64_t port{args.GetIntArg("-datumport", DEFAULT_DATUM_PORT)};
    const int64_t max_clients{args.GetIntArg("-datummaxclients", DEFAULT_DATUM_MAX_CLIENTS)};
    const int64_t max_per_ip{args.GetIntArg("-datummaxperip", DEFAULT_DATUM_MAX_PER_IP)};
    const int64_t difficulty{args.GetIntArg("-datumdiff", DEFAULT_DATUM_DIFFICULTY)};
    if (port < 1 || port > 65535) error = Untranslated("-datumport must be between 1 and 65535");
    else if (max_clients < 1 || max_clients > 4096) error = Untranslated("-datummaxclients must be between 1 and 4096");
    else if (max_per_ip < 1 || max_per_ip > max_clients) error = Untranslated("-datummaxperip must be positive and no greater than -datummaxclients");
    else if (difficulty < 1 || difficulty > 2147483647) error = Untranslated("-datumdiff must be between 1 and 2147483647");
    else if (!LookupHost(args.GetArg("-datumlisten", "127.0.0.1"), /*fAllowLookup=*/false)) error = Untranslated("-datumlisten must be a numeric IPv4 or IPv6 address");
    if (!error.empty()) return false;

    const bool datum_upnp{args.GetBoolArg("-datumupnp", DEFAULT_DATUM_UPNP)};
#ifndef USE_UPNP
    if (datum_upnp) {
        error = Untranslated("-datumupnp=1 requires a build with UPnP support");
        return false;
    }
#else
    if (datum_upnp) {
        const auto listen_addr{LookupHost(args.GetArg("-datumlisten", "127.0.0.1"), /*fAllowLookup=*/false)};
        if (!listen_addr || !listen_addr->IsIPv4() || (listen_addr->IsLocal() && !listen_addr->IsBindAny())) {
            error = Untranslated("-datumupnp=1 requires a non-loopback IPv4 -datumlisten (0.0.0.0 is allowed)");
            return false;
        }
    }
#endif // USE_UPNP

    if (args.GetBoolArg("-datumauth", DEFAULT_DATUM_AUTH) &&
        (args.GetArg("-datumuser", "").empty() || args.GetArg("-datumpassword", "").empty())) {
        error = Untranslated("-datum=1 with authentication requires -datumuser and -datumpassword");
        return false;
    }
    const std::string datum_user{args.GetArg("-datumuser", "")};
    if (datum_user.size() > 191 || std::any_of(datum_user.begin(), datum_user.end(), [](unsigned char c) { return c < 0x20 || c == 0x7f; })) {
        error = Untranslated("-datumuser must be at most 191 bytes and contain no control characters");
        return false;
    }
    const std::string address{args.GetArg("-datumaddress", "")};
    if (address.empty() || !IsValidDestinationString(address, Params())) {
        error = Untranslated("-datumaddress is missing or invalid for the active Purity network");
        return false;
    }
    if (args.GetArg("-datumcoinbasetag", "Bitcoin Purity").size() > 63) {
        error = Untranslated("-datumcoinbasetag must be at most 63 bytes");
        return false;
    }
    if (args.IsArgSet("-datumrpcurl") && !IsLoopbackRpcUrl(args.GetArg("-datumrpcurl", ""))) {
        error = Untranslated("-datumrpcurl must be a loopback HTTP URL without embedded credentials");
        return false;
    }
    const bool datum_user_set{args.IsArgSet("-datumrpcuser")};
    const bool datum_password_set{args.IsArgSet("-datumrpcpassword")};
    if (datum_user_set != datum_password_set) {
        error = Untranslated("-datumrpcuser and -datumrpcpassword must be configured together");
        return false;
    }
    return true;
}

bool StartDatum(node::NodeContext& node, bilingual_str& error)
{
    const ArgsManager& args{*Assert(node.args)};
    if (!args.GetBoolArg("-datum", false)) return true;

    std::string rpc_user;
    std::string rpc_password;
    if (!GetCredentialPair(args, rpc_user, rpc_password, error)) return false;

    const std::string address{args.GetArg("-datumaddress", "")};
    const CScript payout_script{GetScriptForDestination(DecodeDestination(address))};
    if (payout_script.empty() || payout_script.size() > 64) {
        error = Untranslated("-datumaddress produced an unsupported payout script");
        return false;
    }

    const int64_t rpc_port{args.GetIntArg("-rpcport", BaseParams().RPCPort())};
    const std::string rpc_url{args.GetArg("-datumrpcurl", strprintf("http://127.0.0.1:%d", rpc_port))};
    const std::string listen{args.GetArg("-datumlisten", "127.0.0.1")};
    const std::string auth_user{args.GetArg("-datumuser", "")};
    const std::string auth_password{args.GetArg("-datumpassword", "")};
    const std::string coinbase_tag{args.GetArg("-datumcoinbasetag", "Bitcoin Purity")};
    const bool datum_upnp{args.GetBoolArg("-datumupnp", DEFAULT_DATUM_UPNP)};

    datum_embedded_config config{
        .listen_address = listen.c_str(),
        .listen_port = static_cast<uint16_t>(args.GetIntArg("-datumport", DEFAULT_DATUM_PORT)),
        .max_clients = static_cast<uint32_t>(args.GetIntArg("-datummaxclients", DEFAULT_DATUM_MAX_CLIENTS)),
        .max_clients_per_ip = static_cast<uint32_t>(args.GetIntArg("-datummaxperip", DEFAULT_DATUM_MAX_PER_IP)),
        .auth_required = args.GetBoolArg("-datumauth", DEFAULT_DATUM_AUTH),
        .auth_user = auth_user.c_str(),
        .auth_password = auth_password.c_str(),
        .auth_timeout_seconds = DEFAULT_DATUM_AUTH_TIMEOUT,
        .rpc_url = rpc_url.c_str(),
        .rpc_user = rpc_user.c_str(),
        .rpc_password = rpc_password.c_str(),
        .rpc_cookie_file = "",
        .payout_script = payout_script.data(),
        .payout_script_len = payout_script.size(),
        .payout_address = address.c_str(),
        .share_difficulty = static_cast<uint64_t>(args.GetIntArg("-datumdiff", DEFAULT_DATUM_DIFFICULTY)),
        .coinbase_tag = coinbase_tag.c_str(),
    };
    std::array<char, 512> c_error{};
    {
        std::lock_guard lock{g_datum_state_mutex};
        g_datum_state.node = &node;
    }
    if (datum_embedded_start(&config, c_error.data(), c_error.size()) != 0) {
        std::lock_guard lock{g_datum_state_mutex};
        g_datum_state.node = nullptr;
        error = Untranslated(strprintf("Unable to start embedded DATUM: %s", c_error.data()));
        return false;
    }

    {
        std::lock_guard lock{g_datum_state_mutex};
        g_datum_state.enabled = true;
        g_datum_state.listen = listen;
        g_datum_state.port = config.listen_port;
        g_datum_state.share_difficulty = config.share_difficulty;
        g_datum_state.upnp = datum_upnp;
        g_datum_state.auth_required = config.auth_required;
        g_datum_state.payout_address = address;
        g_datum_state.coinbase_tag = coinbase_tag;
    }
    g_datum_validation = std::make_unique<DatumValidationInterface>();
    Assert(node.validation_signals)->RegisterValidationInterface(g_datum_validation.get());
    if (datum_upnp && !config.auth_required) {
        LogWarning("[datum] UPnP mapping is enabled while Stratum authentication is disabled; the DATUM port is public");
    }
    if (datum_upnp) StartDatumUpnp(config.listen_port);
    LogInfo("[datum] subsystem started; Stratum configured on %s:%u", listen, config.listen_port);
    return true;
}

void InterruptDatum()
{
    datum_embedded_interrupt();
#ifdef USE_UPNP
    g_datum_upnp_interrupt();
#endif // USE_UPNP
}

void StopDatum(node::NodeContext* node)
{
    DatumRuntimeState runtime;
    {
        std::lock_guard lock{g_datum_state_mutex};
        runtime = g_datum_state;
    }
    if (!runtime.enabled) return;
    node::NodeContext* context{node ? node : runtime.node};
    if (context && context->validation_signals && g_datum_validation) {
        context->validation_signals->UnregisterValidationInterface(g_datum_validation.get());
    }
    g_datum_validation.reset();
    StopDatumUpnp();
    datum_embedded_stop();
    {
        std::lock_guard lock{g_datum_state_mutex};
        g_datum_state = {};
    }
    LogInfo("[datum] subsystem stopped");
}

double DifficultyFromCompact(uint32_t bits)
{
    if ((bits & 0x00ffffff) == 0) return 0;
    int shift{static_cast<int>((bits >> 24) & 0xff)};
    double difficulty{static_cast<double>(0x0000ffff) / static_cast<double>(bits & 0x00ffffff)};
    while (shift < 29) { difficulty *= 256.0; ++shift; }
    while (shift > 29) { difficulty /= 256.0; --shift; }
    return difficulty;
}

DatumStatusSnapshot GetDatumStatusSnapshot(bool include_miners)
{
    DatumRuntimeState runtime;
    DatumMappingState mapping;
    {
        std::lock_guard lock{g_datum_state_mutex};
        runtime = g_datum_state;
    }
    {
        std::lock_guard lock{g_datum_mapping_mutex};
        mapping = g_datum_mapping;
    }
    datum_embedded_stats stats{};
    datum_embedded_get_stats(&stats);
    DatumStatusSnapshot result;
    result.enabled = runtime.enabled;
    result.running = stats.running;
    result.status = !runtime.enabled ? "Disabled" : stats.stopping ? "Stopping" : !stats.running || stats.current_height == 0 ? "Starting" : stats.last_template_update_ms && !stats.last_template_success ? "Error" : "Running";
    result.auth_required = runtime.auth_required;
    result.listen = runtime.listen;
    result.port = runtime.port;
    result.payout_address = runtime.payout_address;
    result.configured_payout_address = gArgs.GetArg("-datumaddress", "");
    result.coinbase_tag = runtime.coinbase_tag;
    result.configured_coinbase_tag = gArgs.GetArg("-datumcoinbasetag", "Bitcoin Purity");
    result.session_started_ms = stats.session_started_ms;
    result.mapping_requested = runtime.upnp || mapping.requested;
    result.mapping_active = mapping.active;
    result.mapping_protocol = mapping.protocol;
    result.mapping_external = mapping.external;
    result.mapping_lifetime = mapping.lifetime;
    result.mapping_updated_ms = mapping.updated_ms;
    result.mapping_error = mapping.error;
    result.share_difficulty = stats.running ? datum_embedded_get_share_difficulty() : runtime.share_difficulty;
    result.clients = stats.clients;
    result.subscribed_clients = stats.subscribed_clients;
    result.authorized_clients = stats.authorized_clients;
    result.accepted_shares = stats.accepted_shares;
    result.rejected_shares = stats.rejected_shares;
    result.session_accepted_shares = stats.session_accepted_shares;
    result.session_rejected_shares = stats.session_rejected_shares;
    result.last_share_time_ms = stats.last_share_time_ms;
    result.estimated_hashrate_ths = stats.estimated_hashrate_ths;
    result.current_height = stats.current_height;
    result.job_id = stats.job_id;
    result.job_created_ms = stats.job_created_ms;
    result.previous_block_hash = stats.previous_block_hash;
    result.nbits = stats.nbits;
    result.network_difficulty = DifficultyFromCompact(stats.nbits);
    result.transaction_count = stats.transaction_count;
    result.template_size = stats.template_size;
    result.template_weight = stats.template_weight;
    result.coinbase_value = stats.coinbase_value;
    result.last_template_update_ms = stats.last_template_update_ms;
    result.last_template_success = stats.last_template_success;
    result.last_template_error = stats.last_template_error;
    result.block_candidates = stats.block_candidates;
    result.block_submissions_accepted = stats.block_submissions_accepted;
    result.block_submissions_rejected = stats.block_submissions_rejected;
    result.last_block_time_ms = stats.last_block_time_ms;
    result.last_block_hash = stats.last_block_hash;
    result.last_block_result = stats.last_block_result;
    result.last_rejected_share_time_ms = stats.last_rejected_share_time_ms;
    result.last_rejected_share_reason = stats.last_rejected_share_reason;
    result.rejected_unknown_work = stats.rejected_unknown_work;
    result.rejected_high_hash = stats.rejected_high_hash;
    result.rejected_stale = stats.rejected_stale;
    result.rejected_duplicate = stats.rejected_duplicate;
    result.rejected_other = stats.rejected_other;
    if (include_miners && stats.clients > 0) {
        std::vector<datum_embedded_miner_stats> miners(stats.clients);
        miners.resize(datum_embedded_get_miner_stats(miners.data(), miners.size()));
        result.miners.reserve(miners.size());
        for (const auto& miner : miners) {
            result.miners.push_back({
                .worker = miner.worker,
                .remote_host = miner.remote_host,
                .user_agent = miner.user_agent,
                .subscribed = miner.subscribed,
                .authorized = miner.authorized,
                .connected_since_ms = miner.connected_since_ms,
                .current_difficulty = miner.current_difficulty,
                .estimated_hashrate_ths = miner.estimated_hashrate_ths,
                .accepted_shares = miner.accepted_shares,
                .rejected_shares = miner.rejected_shares,
                .last_share_time_ms = miner.last_share_time_ms,
            });
        }
    }
    return result;
}

UniValue GetDatumInfo()
{
    const DatumStatusSnapshot snapshot{GetDatumStatusSnapshot(/*include_miners=*/false)};
    UniValue result{UniValue::VOBJ};
    result.pushKV("enabled", snapshot.enabled);
    result.pushKV("running", snapshot.running);
    result.pushKV("status", snapshot.status);
    result.pushKV("listen", snapshot.listen);
    result.pushKV("port", snapshot.port);
    result.pushKV("upnp", snapshot.mapping_requested);
    result.pushKV("auth_required", snapshot.auth_required);
    result.pushKV("clients", snapshot.clients);
    result.pushKV("subscribed_clients", snapshot.subscribed_clients);
    result.pushKV("authorized_clients", snapshot.authorized_clients);
    result.pushKV("share_difficulty", snapshot.share_difficulty);
    result.pushKV("accepted_shares", snapshot.accepted_shares);
    result.pushKV("rejected_shares", snapshot.rejected_shares);
    result.pushKV("session_accepted_shares", snapshot.session_accepted_shares);
    result.pushKV("session_rejected_shares", snapshot.session_rejected_shares);
    result.pushKV("session_started", snapshot.session_started_ms / 1000);
    result.pushKV("last_share_time", snapshot.last_share_time_ms / 1000);
    result.pushKV("estimated_hashrate_ths", snapshot.estimated_hashrate_ths);
    result.pushKV("current_height", snapshot.current_height);

    UniValue mapping{UniValue::VOBJ};
    mapping.pushKV("requested", snapshot.mapping_requested);
    mapping.pushKV("active", snapshot.mapping_active);
    mapping.pushKV("protocol", snapshot.mapping_protocol);
    mapping.pushKV("external", snapshot.mapping_external);
    mapping.pushKV("lifetime", snapshot.mapping_lifetime);
    mapping.pushKV("updated", snapshot.mapping_updated_ms / 1000);
    mapping.pushKV("error", snapshot.mapping_error);
    result.pushKV("port_mapping", std::move(mapping));

    UniValue job{UniValue::VOBJ};
    job.pushKV("id", snapshot.job_id);
    job.pushKV("height", snapshot.current_height);
    job.pushKV("created", snapshot.job_created_ms / 1000);
    job.pushKV("previous_block_hash", snapshot.previous_block_hash);
    job.pushKV("nbits", strprintf("%08x", snapshot.nbits));
    job.pushKV("network_difficulty", snapshot.network_difficulty);
    job.pushKV("transactions", snapshot.transaction_count);
    job.pushKV("size", snapshot.template_size);
    job.pushKV("weight", snapshot.template_weight);
    job.pushKV("coinbase_value", snapshot.coinbase_value);
    job.pushKV("last_template_update", snapshot.last_template_update_ms / 1000);
    job.pushKV("last_template_success", snapshot.last_template_success);
    job.pushKV("last_template_error", snapshot.last_template_error);
    result.pushKV("current_job", std::move(job));

    UniValue blocks{UniValue::VOBJ};
    blocks.pushKV("candidates", snapshot.block_candidates);
    blocks.pushKV("accepted", snapshot.block_submissions_accepted);
    blocks.pushKV("rejected", snapshot.block_submissions_rejected);
    blocks.pushKV("last_time", snapshot.last_block_time_ms / 1000);
    blocks.pushKV("last_hash", snapshot.last_block_hash);
    blocks.pushKV("last_result", snapshot.last_block_result);
    blocks.pushKV("last_share_rejection_time", snapshot.last_rejected_share_time_ms / 1000);
    blocks.pushKV("last_share_rejection_reason", snapshot.last_rejected_share_reason);
    UniValue rejection_counts{UniValue::VOBJ};
    rejection_counts.pushKV("unknown_work", snapshot.rejected_unknown_work);
    rejection_counts.pushKV("high_hash", snapshot.rejected_high_hash);
    rejection_counts.pushKV("stale", snapshot.rejected_stale);
    rejection_counts.pushKV("duplicate", snapshot.rejected_duplicate);
    rejection_counts.pushKV("other", snapshot.rejected_other);
    blocks.pushKV("share_rejections", std::move(rejection_counts));
    result.pushKV("block_submission", std::move(blocks));
    return result;
}

bool SetDatumDifficulty(const int64_t difficulty, std::string& error)
{
    if (difficulty < 1 || difficulty > MAX_DATUM_DIFFICULTY) {
        error = strprintf("share difficulty must be between 1 and %d", MAX_DATUM_DIFFICULTY);
        return false;
    }
    std::array<char, 256> c_error{};
    if (datum_embedded_update_share_difficulty(static_cast<uint64_t>(difficulty), c_error.data(), c_error.size()) != 0) {
        error = c_error.data();
        return false;
    }
    {
        std::lock_guard lock{g_datum_state_mutex};
        g_datum_state.share_difficulty = difficulty;
    }
    LogInfo("[datum] share difficulty updated at runtime to %d", static_cast<int>(difficulty));
    return true;
}

bool SetDatumPayoutAndCoinbase(const std::string& address, const std::string& coinbase_tag, std::string& error)
{
    if (address.empty() || !IsValidDestinationString(address, Params())) {
        error = "payout address is invalid for the active Purity network";
        return false;
    }
    if (coinbase_tag.size() > 63) {
        error = "coinbase tag must be at most 63 bytes";
        return false;
    }
    const CScript payout_script{GetScriptForDestination(DecodeDestination(address))};
    if (payout_script.empty() || payout_script.size() > 64) {
        error = "payout address produced an unsupported payout script";
        return false;
    }
    std::array<char, 256> c_error{};
    if (datum_embedded_update_payout_and_coinbase(
            reinterpret_cast<const unsigned char*>(payout_script.data()), payout_script.size(),
            coinbase_tag.c_str(), c_error.data(), c_error.size()) != 0) {
        error = c_error.data();
        return false;
    }
    {
        std::lock_guard lock{g_datum_state_mutex};
        g_datum_state.payout_address = address;
        g_datum_state.coinbase_tag = coinbase_tag;
    }
    LogInfo("[datum] payout address and Coinbase tag updated at runtime");
    return true;
}

} // namespace mining

extern "C" void datum_bridge_log(int level, const char* message)
{
    switch (level) {
    case DLOG_LEVEL_FATAL:
    case DLOG_LEVEL_ERROR:
        LogError("[datum] %s", message);
        break;
    case DLOG_LEVEL_WARN:
        LogWarning("[datum] %s", message);
        break;
    default:
        LogInfo("[datum] %s", message);
        break;
    }
}

extern "C" void datum_bridge_fatal_error(const char* message)
{
    LogError("[datum] fatal error: %s", message);
    datum_embedded_request_stop();
    if (mining::g_datum_state.node && mining::g_datum_state.node->shutdown_request) {
        mining::g_datum_state.node->shutdown_request();
    }
}
