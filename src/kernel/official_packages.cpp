// Copyright (c) 2025 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/official_packages.h>

#include <chainparams.h>
#include <common/args.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <pubkey.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr int MIN_PRUNE_MIB{550};

//! Compressed secp256k1 public key used to verify remote package manifests.
//! Generate and rotate with contrib/official-packages/sign-manifest.py.
constexpr const char* OFFICIAL_PACKAGES_SIGNING_PUBKEY_HEX =
    "02f7b5f924d626f3b2378d9bcaf81c944800deb1172fb13a212428c05e4cc9509a";

std::optional<CPubKey> EmbeddedSigningPubKey()
{
    const auto bytes = ParseHex(OFFICIAL_PACKAGES_SIGNING_PUBKEY_HEX);
    if (bytes.size() != CPubKey::COMPRESSED_SIZE) {
        LogPrintf("Official packages config: invalid embedded signing pubkey\n");
        return std::nullopt;
    }
    CPubKey pubkey(bytes);
    if (!pubkey.IsFullyValid()) {
        LogPrintf("Official packages config: embedded signing pubkey is not valid\n");
        return std::nullopt;
    }
    return pubkey;
}

std::string ToLowerAscii(std::string_view input)
{
    std::string out(input);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
    return out;
}

bool IsAllowedDownloadHost(std::string_view host)
{
    static constexpr std::string_view ALLOWED_HOSTS[] = {
        "downloads.bitcoinpurity.org",
    };
    const std::string lowered = ToLowerAscii(host);
    for (const auto allowed : ALLOWED_HOSTS) {
        if (lowered == allowed) return true;
    }
    return false;
}

std::optional<std::string_view> ExtractUriHost(std::string_view uri)
{
    constexpr std::string_view HTTPS_PREFIX{"https://"};
    if (!uri.starts_with(HTTPS_PREFIX)) return std::nullopt;
    uri.remove_prefix(HTTPS_PREFIX.size());

    if (uri.find('@') != std::string_view::npos) return std::nullopt;
    const size_t slash = uri.find('/');
    const size_t colon = uri.find(':');
    const size_t end = std::min(slash, colon);
    if (end == 0) return std::nullopt;
    return uri.substr(0, end);
}

bool PathComponentIsDotOrDotDot(std::string_view component)
{
    return component == "." || component == "..";
}

void SplitPathComponents(std::string_view path, const std::function<void(std::string_view)>& fn)
{
    size_t start = 0;
    while (start < path.size()) {
        const size_t slash = path.find_first_of("/\\", start);
        const size_t end = slash == std::string_view::npos ? path.size() : slash;
        if (end > start) {
            fn(path.substr(start, end - start));
        }
        if (slash == std::string_view::npos) break;
        start = slash + 1;
    }
}

std::optional<uint256> ParseHashHex(const std::string& hex, const std::string& field_name)
{
    const auto hash = uint256::FromUserHex(hex);
    if (!hash) {
        LogPrintf("Official packages config: invalid %s hash %s\n", field_name, hex);
        return std::nullopt;
    }
    return *hash;
}

std::optional<uint256> ParseStandardSha256Hex(const std::string& hex)
{
    const auto bytes = TryParseHex<uint8_t>(hex);
    if (!bytes || bytes->size() != 32) {
        LogPrintf("Official packages config: invalid archive_sha256 %s\n", hex);
        return std::nullopt;
    }
    if (std::all_of(bytes->begin(), bytes->end(), [](uint8_t b) { return b == 0; })) {
        return std::nullopt;
    }
    uint256 hash;
    std::copy(bytes->begin(), bytes->end(), hash.begin());
    return hash;
}

std::optional<OfficialDataPackage> ParsePackage(
    const UniValue& entry, OfficialPackageTrustPolicy trust_policy)
{
    if (!entry.isObject()) return std::nullopt;

    OfficialDataPackage package;
    try {
        if (!entry.exists("id")) return std::nullopt;
        package.id = entry.find_value("id").get_str();
        if (package.id.empty()) return std::nullopt;

        if (!entry.exists("snapshot_height")) return std::nullopt;
        package.snapshot_height = entry.find_value("snapshot_height").getInt<int>();
        if (package.snapshot_height <= 0) return std::nullopt;

        if (!entry.exists("base_blockhash")) return std::nullopt;
        const auto base_hash = ParseHashHex(entry.find_value("base_blockhash").get_str(), "base_blockhash");
        if (!base_hash) return std::nullopt;
        package.base_blockhash = *base_hash;

        package.prune_mib = 0;
        if (entry.exists("prune_mib")) {
            package.prune_mib = entry.find_value("prune_mib").getInt<int>();
        }
        if (package.prune_mib < 0) return std::nullopt;
        if (package.prune_mib > 0 && package.prune_mib < MIN_PRUNE_MIB) {
            LogPrintf("Official packages config: package %s prune_mib below minimum (%d)\n", package.id, MIN_PRUNE_MIB);
            return std::nullopt;
        }

        if (!entry.exists("download_uri")) return std::nullopt;
        package.download_uri = entry.find_value("download_uri").get_str();
        if (package.download_uri.empty()) return std::nullopt;
        if (!IsOfficialDownloadUriAllowed(package.download_uri, trust_policy)) {
            LogPrintf("Official packages config: rejected download_uri for package %s\n", package.id);
            return std::nullopt;
        }

        if (!entry.exists("archive_sha256")) return std::nullopt;
        const auto archive_hash = ParseStandardSha256Hex(entry.find_value("archive_sha256").get_str());
        if (!archive_hash) return std::nullopt;
        package.archive_sha256 = *archive_hash;

        package.archive_size_bytes = 0;
        if (entry.exists("archive_size_bytes")) {
            package.archive_size_bytes = entry.find_value("archive_size_bytes").getInt<uint64_t>();
        }
        package.extracted_size_bytes = 0;
        if (entry.exists("extracted_size_bytes")) {
            package.extracted_size_bytes = entry.find_value("extracted_size_bytes").getInt<uint64_t>();
        }
    } catch (const std::runtime_error& e) {
        LogPrintf("Official packages config: failed to parse package entry: %s\n", e.what());
        return std::nullopt;
    }

    return package;
}

std::vector<std::string> OfficialPackagesConfigFilenames(ChainType chain)
{
    std::vector<std::string> names;
    names.push_back("official-packages-" + ChainTypeToString(chain) + ".json");
    switch (chain) {
    case ChainType::MAIN:
        names.push_back("official-packages-mainnet.json");
        break;
    case ChainType::TESTNET:
        names.push_back("official-packages-testnet.json");
        break;
    default:
        break;
    }
    names.push_back("official-packages.json");
    return names;
}

std::optional<fs::path> ResolveExplicitOfficialPackagesPath(const ArgsManager& args)
{
    const fs::path arg_path = fs::PathFromString(args.GetArg("-officialpackages", ""));
    if (arg_path.empty()) return std::nullopt;
    if (arg_path.is_absolute() && fs::exists(arg_path)) {
        return arg_path;
    }
    if (fs::exists(arg_path)) {
        return fs::absolute(arg_path);
    }
    const fs::path datadir_path = AbsPathForConfigVal(args, arg_path, /*net_specific=*/false);
    if (fs::exists(datadir_path)) {
        return datadir_path;
    }
    return datadir_path;
}

std::optional<fs::path> FindDatadirOfficialPackagesPath(const ArgsManager& args, ChainType chain)
{
    for (const auto& filename : OfficialPackagesConfigFilenames(chain)) {
        const fs::path datadir_path = AbsPathForConfigVal(args, fs::PathFromString(filename), /*net_specific=*/false);
        if (fs::exists(datadir_path)) return datadir_path;
    }
    return std::nullopt;
}

} // namespace

bool IsOfficialDownloadUriAllowed(const std::string& uri, OfficialPackageTrustPolicy trust_policy)
{
    if (uri.empty()) return false;
    if (trust_policy == OfficialPackageTrustPolicy::LOCAL) return true;

    const std::string_view uri_view{uri};
    if (!uri_view.starts_with("https://")) {
        LogPrintf("Official packages config: download_uri must use HTTPS: %s\n", uri);
        return false;
    }

    const auto host = ExtractUriHost(uri_view);
    if (!host || !IsAllowedDownloadHost(*host)) {
        LogPrintf("Official packages config: download_uri host is not allowlisted: %s\n", uri);
        return false;
    }
    return true;
}

bool IsOfficialSnapshotTrusted(
    const CChainParams& params, int snapshot_height, const uint256& base_blockhash)
{
    if (snapshot_height <= 0 || base_blockhash.IsNull()) return false;

    if (const auto assumeutxo = params.AssumeutxoForHeight(snapshot_height)) {
        return assumeutxo->blockhash == base_blockhash;
    }

    const auto& checkpoints = params.Checkpoints().mapCheckpoints;
    const auto checkpoint = checkpoints.find(snapshot_height);
    if (checkpoint != checkpoints.end()) {
        return checkpoint->second == base_blockhash;
    }

    return false;
}

void CanonicalizeJsonValue(UniValue& value)
{
    if (value.isObject()) {
        std::map<std::string, UniValue> fields;
        value.getObjMap(fields);
        value.clear();
        value.setObject();
        for (auto& [key, child] : fields) {
            CanonicalizeJsonValue(child);
            value.pushKV(key, std::move(child));
        }
        return;
    }
    if (value.isArray()) {
        std::vector<UniValue> normalized;
        normalized.reserve(value.size());
        for (size_t i = 0; i < value.size(); ++i) {
            UniValue child = value[i];
            CanonicalizeJsonValue(child);
            normalized.push_back(std::move(child));
        }
        value.clear();
        value.setArray();
        for (auto& child : normalized) {
            value.push_back(std::move(child));
        }
    }
}

namespace {

std::string OfficialPackagesManifestPayload(const std::string& json_contents)
{
    UniValue json;
    if (!json.read(json_contents) || !json.isObject()) {
        return {};
    }

    std::map<std::string, UniValue> fields;
    json.getObjMap(fields);
    fields.erase("signature");

    UniValue unsigned_json;
    unsigned_json.setObject();
    for (const auto& [key, value] : fields) {
        unsigned_json.pushKV(key, value);
    }
    CanonicalizeJsonValue(unsigned_json);
    return unsigned_json.write(0, 0);
}

} // namespace

uint256 OfficialPackagesManifestDigest(const std::string& json_contents)
{
    const std::string payload = OfficialPackagesManifestPayload(json_contents);
    if (payload.empty()) {
        return {};
    }
    uint256 digest;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(payload.data()), payload.size())
        .Finalize(digest.begin());
    return digest;
}

bool VerifyOfficialPackagesManifestSignature(
    const std::string& json_contents, const CPubKey& signing_pubkey)
{
    if (!signing_pubkey.IsFullyValid()) return false;

    UniValue json;
    if (!json.read(json_contents) || !json.isObject()) return false;
    if (!json.exists("signature")) return false;

    const std::string signature_b64 = json.find_value("signature").get_str();
    const auto signature_bytes = DecodeBase64(signature_b64);
    if (!signature_bytes || signature_bytes->empty()) return false;

    const uint256 digest = OfficialPackagesManifestDigest(json_contents);
    if (digest.IsNull()) return false;

    return signing_pubkey.Verify(digest, *signature_bytes);
}

bool IsZipArchiveEntryPathSafe(std::string_view entry_path)
{
    if (entry_path.empty()) return false;
    if (entry_path[0] == '/' || entry_path[0] == '\\') return false;
    if (entry_path.size() >= 2 && std::isalpha(static_cast<unsigned char>(entry_path[0])) && entry_path[1] == ':') {
        return false;
    }

    bool safe = true;
    SplitPathComponents(entry_path, [&](std::string_view component) {
        if (PathComponentIsDotOrDotDot(component)) {
            safe = false;
        }
    });
    return safe;
}

std::optional<std::string> GetDefaultOfficialPackagesUrl(ChainType chain)
{
    switch (chain) {
    case ChainType::MAIN:
        return "https://downloads.bitcoinpurity.org/official-packages-mainnet.json";
    case ChainType::TESTNET:
        return "https://downloads.bitcoinpurity.org/official-packages-testnet.json";
    default:
        return std::nullopt;
    }
}

std::optional<fs::path> FindDatadirOfficialPackagesConfigPath(const ArgsManager& args, ChainType chain)
{
    return FindDatadirOfficialPackagesPath(args, chain);
}

std::vector<OfficialDataPackage> ParseOfficialDataPackagesFromJson(
    const std::string& json_contents,
    const std::string& source_label,
    OfficialPackageTrustPolicy trust_policy)
{
    std::vector<OfficialDataPackage> packages;
    UniValue json;
    if (!json.read(json_contents)) {
        LogPrintf("Official packages config: failed to parse JSON from %s\n", source_label);
        return packages;
    }
    if (!json.isObject()) {
        LogPrintf("Official packages config: expected JSON object from %s\n", source_label);
        return packages;
    }

    if (trust_policy == OfficialPackageTrustPolicy::STRICT) {
        const auto signing_pubkey = EmbeddedSigningPubKey();
        if (!signing_pubkey) {
            LogPrintf("Official packages config: missing embedded signing pubkey\n");
            return packages;
        }
        if (!VerifyOfficialPackagesManifestSignature(json_contents, *signing_pubkey)) {
            LogPrintf("Official packages config: invalid or missing manifest signature from %s\n", source_label);
            return packages;
        }
    }

    const auto chainparams = CreateChainParams(gArgs, gArgs.GetChainType());
    if (!chainparams) {
        LogPrintf("Official packages config: could not resolve chain params\n");
        return packages;
    }

    const UniValue& list = json.exists("packages") ? json.find_value("packages") : json;
    if (!list.isArray()) {
        LogPrintf("Official packages config: expected \"packages\" array from %s\n", source_label);
        return packages;
    }

    for (size_t i = 0; i < list.size(); ++i) {
        const auto package = ParsePackage(list[i], trust_policy);
        if (!package) {
            LogPrintf("Official packages config: skipping invalid entry at index %u from %s\n", i, source_label);
            continue;
        }
        if (!IsOfficialSnapshotTrusted(*chainparams, package->snapshot_height, package->base_blockhash)) {
            LogPrintf("Official packages config: snapshot not trusted for package %s\n", package->id);
            continue;
        }
        packages.push_back(*package);
    }

    LogPrintf("Loaded %u official data package(s) from %s\n", packages.size(), source_label);
    return packages;
}

std::vector<OfficialDataPackage> LoadOfficialDataPackages(const ArgsManager& args, ChainType chain)
{
    std::optional<fs::path> config_path;
    if (args.IsArgSet("-officialpackages")) {
        config_path = ResolveExplicitOfficialPackagesPath(args);
    } else {
        config_path = FindDatadirOfficialPackagesPath(args, chain);
    }

    if (!config_path) {
        LogPrintf("Official packages local config not found\n");
        return {};
    }

    if (!fs::exists(*config_path)) {
        LogPrintf("Official packages config not found: %s\n", fs::PathToString(*config_path));
        return {};
    }

    std::ifstream file{*config_path, std::ios::binary};
    if (!file) return {};
    const std::string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return ParseOfficialDataPackagesFromJson(
        contents, fs::PathToString(*config_path), OfficialPackageTrustPolicy::LOCAL);
}

std::optional<OfficialDataPackage> FindOfficialDataPackage(
    const std::vector<OfficialDataPackage>& packages, const std::string& id)
{
    for (const auto& package : packages) {
        if (package.id == id) return package;
    }
    return std::nullopt;
}
