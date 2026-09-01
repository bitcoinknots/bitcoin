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
class CChainParams;
class CPubKey;

/**
 * Trust policy for official package manifests and download URIs.
 *
 * REMOTE_SIGNED applies to manifests fetched from downloads.bitcoinpurity.org and
 * requires a valid detached signature plus HTTPS download URIs on an allowlist.
 * LOCAL applies to user-provided manifests (-officialpackages or datadir file)
 * and skips signature and URI host checks so developers can test offline.
 */
enum class OfficialPackageTrustPolicy {
    REMOTE_SIGNED,
    LOCAL,
};

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
    const std::string& json_contents,
    const std::string& source_label,
    OfficialPackageTrustPolicy trust_policy = OfficialPackageTrustPolicy::LOCAL);

std::optional<OfficialDataPackage> FindOfficialDataPackage(
    const std::vector<OfficialDataPackage>& packages, const std::string& id);

/** Whether a download URI satisfies the trust policy (HTTPS + host allowlist for REMOTE_SIGNED). */
bool IsOfficialDownloadUriAllowed(const std::string& uri, OfficialPackageTrustPolicy trust_policy);

/**
 * Whether a package snapshot may be offered for this chain.
 *
 * If snapshot_height is already an assumeutxo or checkpoint pin, the hash must
 * match. Otherwise any post-activation height is accepted so signed remote
 * manifests can publish new packages without a client release.
 */
bool IsOfficialSnapshotTrusted(
    const CChainParams& params, int snapshot_height, const uint256& base_blockhash);

/** SHA-256 digest of a manifest with any top-level signature field removed. */
uint256 OfficialPackagesManifestDigest(const std::string& json_contents);

/** Verify a detached ECDSA signature over OfficialPackagesManifestDigest(). */
bool VerifyOfficialPackagesManifestSignature(
    const std::string& json_contents, const CPubKey& signing_pubkey);

/** Whether a zip archive entry path is safe to extract (no zip-slip). */
bool IsZipArchiveEntryPathSafe(std::string_view entry_path);

#endif // BITCOIN_KERNEL_OFFICIAL_PACKAGES_H
