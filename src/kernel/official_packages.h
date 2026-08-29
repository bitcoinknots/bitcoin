// Copyright (c) 2025 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_OFFICIAL_PACKAGES_H
#define BITCOIN_KERNEL_OFFICIAL_PACKAGES_H

#include <uint256.h>
#include <util/chaintype.h>
#include <util/fs.h>

#include <optional>
#include <string>
#include <vector>

class ArgsManager;

/**
 * Official pre-built datadir archive offered for fast initial sync.
 * Loaded from a JSON configuration file; not hardcoded in chainparams.
 */
struct OfficialDataPackage {
    std::string id;
    int snapshot_height;
    uint256 base_blockhash;
    int prune_mib; //!< 0 = full node, otherwise automatic prune target in MiB
    std::string download_uri;
    uint256 archive_sha256;
    uint64_t archive_size_bytes;
    uint64_t extracted_size_bytes;
};

/** Default remote JSON URL for the chain, when no local override is configured. */
std::optional<std::string> GetDefaultOfficialPackagesUrl(ChainType chain);

/** Optional per-node override in the datadir (official-packages-<chain>.json). */
std::optional<fs::path> FindDatadirOfficialPackagesConfigPath(const ArgsManager& args, ChainType chain);

/** Load package definitions from a local JSON file (-officialpackages or datadir override). */
std::vector<OfficialDataPackage> LoadOfficialDataPackages(const ArgsManager& args, ChainType chain);

/** Parse package definitions from JSON text (remote manifest or local file contents). */
std::vector<OfficialDataPackage> ParseOfficialDataPackagesFromJson(
    const std::string& json_contents, const std::string& source_label);

std::optional<OfficialDataPackage> FindOfficialDataPackage(
    const std::vector<OfficialDataPackage>& packages, const std::string& id);

#endif // BITCOIN_KERNEL_OFFICIAL_PACKAGES_H
