// Copyright (c) 2025 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/official_packages.h>

#include <common/args.h>
#include <logging.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <algorithm>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

namespace {

constexpr int MIN_PRUNE_MIB{550};

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

std::optional<OfficialDataPackage> ParsePackage(const UniValue& entry)
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
    const std::string& json_contents, const std::string& source_label)
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

    const UniValue& list = json.exists("packages") ? json.find_value("packages") : json;
    if (!list.isArray()) {
        LogPrintf("Official packages config: expected \"packages\" array from %s\n", source_label);
        return packages;
    }

    for (size_t i = 0; i < list.size(); ++i) {
        const auto package = ParsePackage(list[i]);
        if (!package) {
            LogPrintf("Official packages config: skipping invalid entry at index %u from %s\n", i, source_label);
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
    return ParseOfficialDataPackagesFromJson(contents, fs::PathToString(*config_path));
}

std::optional<OfficialDataPackage> FindOfficialDataPackage(
    const std::vector<OfficialDataPackage>& packages, const std::string& id)
{
    for (const auto& package : packages) {
        if (package.id == id) return package;
    }
    return std::nullopt;
}
