// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/official_packages.h>

#include <chainparams.h>
#include <key.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <util/fs.h>
#include <util/zip.h>

#include <cstdint>
#include <fstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

std::string SignManifest(const CKey& key, const std::string& json_contents)
{
    const uint256 digest = OfficialPackagesManifestDigest(json_contents);
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(digest, signature));
    return EncodeBase64(signature);
}

std::string AddManifestSignature(const std::string& unsigned_json, const std::string& signature_b64)
{
    UniValue json;
    BOOST_REQUIRE(json.read(unsigned_json));
    json.pushKV("signature", signature_b64);
    return json.write(0, 0);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(official_packages_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(download_uri_policy)
{
    BOOST_CHECK(IsOfficialDownloadUriAllowed(
        "https://downloads.bitcoinpurity.org/mainnet/pkg.zip", OfficialPackageTrustPolicy::REMOTE_SIGNED));
    BOOST_CHECK(!IsOfficialDownloadUriAllowed(
        "http://downloads.bitcoinpurity.org/mainnet/pkg.zip", OfficialPackageTrustPolicy::REMOTE_SIGNED));
    BOOST_CHECK(!IsOfficialDownloadUriAllowed(
        "https://evil.example/mainnet/pkg.zip", OfficialPackageTrustPolicy::REMOTE_SIGNED));
    BOOST_CHECK(IsOfficialDownloadUriAllowed(
        "http://localhost/pkg.zip", OfficialPackageTrustPolicy::LOCAL));
}

BOOST_AUTO_TEST_CASE(zip_entry_path_safety)
{
    BOOST_CHECK(IsZipArchiveEntryPathSafe("blocks/blk00000.dat"));
    BOOST_CHECK(!IsZipArchiveEntryPathSafe("../bitcoin.conf"));
    BOOST_CHECK(!IsZipArchiveEntryPathSafe("/etc/passwd"));
    BOOST_CHECK(!IsZipArchiveEntryPathSafe("blocks/../../wallets/x"));
}

BOOST_AUTO_TEST_CASE(snapshot_trust_mainnet_assumeutxo)
{
    const auto params = CreateChainParams(m_args, ChainType::MAIN);
    BOOST_REQUIRE(params);
    const uint256 hash = uint256::FromUserHex("0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821").value();
    BOOST_CHECK(IsOfficialSnapshotTrusted(*params, 910000, hash));
    BOOST_CHECK(!IsOfficialSnapshotTrusted(*params, 910000, uint256::ZERO));
    BOOST_CHECK(!IsOfficialSnapshotTrusted(*params, 1, hash));
}

BOOST_AUTO_TEST_CASE(snapshot_trust_allows_unpinned_post_activation_height)
{
    const auto params = CreateChainParams(m_args, ChainType::MAIN);
    BOOST_REQUIRE(params);
    const uint256 package_hash = uint256::FromUserHex("00000000000000040440db37ab428b029ee5dda57d192088c13046d124eeb80b").value();
    BOOST_CHECK(IsOfficialSnapshotTrusted(*params, 961814, package_hash));
    BOOST_CHECK(!IsOfficialSnapshotTrusted(*params, 961814, uint256::ZERO));

    const uint256 activation = uint256::FromUserHex("0000000000000000003ea74f4dafdda7ed4e02c4c1ccb9768e0ca4f9e1a35159").value();
    BOOST_CHECK(IsOfficialSnapshotTrusted(*params, 961637, activation));
    BOOST_CHECK(!IsOfficialSnapshotTrusted(*params, 961637, package_hash));
    BOOST_CHECK(!IsOfficialSnapshotTrusted(*params, 800000, package_hash));
}

BOOST_AUTO_TEST_CASE(parse_published_mainnet_manifest)
{
    // Live https://downloads.bitcoinpurity.org/official-packages-mainnet.json
    const std::string published_json = R"({
  "packages": [
    {
      "id": "mainnet-961814-prune-10gb",
      "snapshot_height": 961814,
      "base_blockhash": "00000000000000040440db37ab428b029ee5dda57d192088c13046d124eeb80b",
      "prune_mib": 10000,
      "download_uri": "https://downloads.bitcoinpurity.org/nodedata/BitcoinPurity-10000-961814-4b9ebf59.zip",
      "archive_sha256": "4b9ebf59002eda73aff911803642c0223bb792660c48f76826780836182e21f1",
      "archive_size_bytes": 30390803377,
      "extracted_size_bytes": 34182117528
    }
  ],
  "signature": "MEYCIQCcjCUf1XDcD1OGNO0bO+AyFG/wMrN7wRXjKBaMd3XsWgIhAOmIKizS3yhsdpL97oAhkm1WgdD2WCjk3fdQwzC7LTYJ"
})";

    const auto packages = ParseOfficialDataPackagesFromJson(
        published_json, "published-mainnet", OfficialPackageTrustPolicy::REMOTE_SIGNED);
    BOOST_REQUIRE_EQUAL(packages.size(), 1U);
    BOOST_CHECK_EQUAL(packages[0].id, "mainnet-961814-prune-10gb");
    BOOST_CHECK_EQUAL(packages[0].snapshot_height, 961814);
    BOOST_CHECK_EQUAL(packages[0].prune_mib, 10000);
    BOOST_CHECK_EQUAL(packages[0].archive_size_bytes, 30390803377ULL);
}

BOOST_AUTO_TEST_CASE(manifest_signature_roundtrip)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();

    const std::string unsigned_json = R"({
  "packages": [
    {
      "id": "mainnet-910000-prune-2gb",
      "snapshot_height": 910000,
      "base_blockhash": "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
      "prune_mib": 1907,
      "download_uri": "https://downloads.bitcoinpurity.org/mainnet/mainnet-910000-prune-2gb.zip",
      "archive_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
})";

    const std::string signed_json = AddManifestSignature(unsigned_json, SignManifest(key, unsigned_json));
    BOOST_CHECK(VerifyOfficialPackagesManifestSignature(signed_json, pubkey));
    BOOST_CHECK(!VerifyOfficialPackagesManifestSignature(unsigned_json, pubkey));
}

// Cross-implementation vector: manifest signed with
// contrib/official-packages/sign-manifest.py (openssl pkeyutl over the
// canonical single-SHA256 digest) must verify with CPubKey::Verify().
BOOST_AUTO_TEST_CASE(manifest_signature_python_tool_vector)
{
    const std::string signed_json = R"({
  "packages": [
    {
      "id": "mainnet-910000-prune-2gb",
      "snapshot_height": 910000,
      "base_blockhash": "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
      "prune_mib": 1907,
      "download_uri": "https://downloads.bitcoinpurity.org/mainnet/mainnet-910000-prune-2gb.zip",
      "archive_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ],
  "signature": "MEQCIG+kvW+rrCkdKQ/0G3UePl9IHnOiaZeDTvsoa2jqxwMNAiAUtHGgE01pso95PeBdABvF4T/BioDbpb27UjIqrn3mRg=="
})";

    const CPubKey pubkey{ParseHex("0234b9bee991cfee1181eb994606ef744517c73365840870e44f4889c65bc09a39")};
    BOOST_REQUIRE(pubkey.IsFullyValid());
    BOOST_CHECK(VerifyOfficialPackagesManifestSignature(signed_json, pubkey));

    // Any change to the signed payload must invalidate the signature.
    std::string tampered = signed_json;
    tampered.replace(tampered.find("prune_mib\": 1907"), 16, "prune_mib\": 1908");
    BOOST_CHECK(!VerifyOfficialPackagesManifestSignature(tampered, pubkey));
}

BOOST_AUTO_TEST_CASE(parse_remote_manifest_requires_signature)
{
    const std::string unsigned_json = R"({
  "packages": [
    {
      "id": "mainnet-910000-prune-2gb",
      "snapshot_height": 910000,
      "base_blockhash": "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
      "prune_mib": 1907,
      "download_uri": "https://downloads.bitcoinpurity.org/mainnet/mainnet-910000-prune-2gb.zip",
      "archive_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
})";

    const auto packages = ParseOfficialDataPackagesFromJson(
        unsigned_json, "test", OfficialPackageTrustPolicy::REMOTE_SIGNED);
    BOOST_CHECK(packages.empty());

    const auto local_packages = ParseOfficialDataPackagesFromJson(
        unsigned_json, "test", OfficialPackageTrustPolicy::LOCAL);
    BOOST_CHECK_EQUAL(local_packages.size(), 1U);
}

namespace {

uint32_t Crc32(std::string_view data)
{
    uint32_t crc = 0xffffffffu;
    for (unsigned char c : data) {
        crc ^= c;
        for (int i = 0; i < 8; ++i) {
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

void AppendU16(std::string& out, uint16_t value)
{
    out.push_back(static_cast<char>(value & 0xff));
    out.push_back(static_cast<char>((value >> 8) & 0xff));
}

void AppendU32(std::string& out, uint32_t value)
{
    out.push_back(static_cast<char>(value & 0xff));
    out.push_back(static_cast<char>((value >> 8) & 0xff));
    out.push_back(static_cast<char>((value >> 16) & 0xff));
    out.push_back(static_cast<char>((value >> 24) & 0xff));
}

void AppendU64(std::string& out, uint64_t value)
{
    AppendU32(out, static_cast<uint32_t>(value));
    AppendU32(out, static_cast<uint32_t>(value >> 32));
}

std::pair<std::string, std::string> BuildStoredZipMembers(const std::vector<std::pair<std::string, std::string>>& files, uint16_t flags = 0)
{
    std::string locals;
    std::string centrals;
    uint32_t offset = 0;
    for (const auto& [name, data] : files) {
        const uint32_t crc = Crc32(data);
        const uint32_t size = static_cast<uint32_t>(data.size());
        std::string local{"PK\x03\x04"};
        AppendU16(local, 20);
        AppendU16(local, flags);
        AppendU16(local, 0);
        AppendU16(local, 0);
        AppendU16(local, 0);
        AppendU32(local, crc);
        AppendU32(local, size);
        AppendU32(local, size);
        AppendU16(local, static_cast<uint16_t>(name.size()));
        AppendU16(local, 0);
        local += name;
        local += data;

        std::string central{"PK\x01\x02"};
        AppendU16(central, 20);
        AppendU16(central, 20);
        AppendU16(central, flags);
        AppendU16(central, 0);
        AppendU16(central, 0);
        AppendU16(central, 0);
        AppendU32(central, crc);
        AppendU32(central, size);
        AppendU32(central, size);
        AppendU16(central, static_cast<uint16_t>(name.size()));
        AppendU16(central, 0);
        AppendU16(central, 0);
        AppendU16(central, 0);
        AppendU16(central, 0);
        AppendU32(central, 0);
        AppendU32(central, offset);
        central += name;

        offset += static_cast<uint32_t>(local.size());
        locals += local;
        centrals += central;
    }
    return {std::move(locals), std::move(centrals)};
}

void WriteStoredZip(const fs::path& path, const std::vector<std::pair<std::string, std::string>>& files, uint16_t flags = 0)
{
    const auto [locals, centrals] = BuildStoredZipMembers(files, flags);
    std::string eocd{"PK\x05\x06"};
    AppendU16(eocd, 0);
    AppendU16(eocd, 0);
    AppendU16(eocd, static_cast<uint16_t>(files.size()));
    AppendU16(eocd, static_cast<uint16_t>(files.size()));
    AppendU32(eocd, static_cast<uint32_t>(centrals.size()));
    AppendU32(eocd, static_cast<uint32_t>(locals.size()));
    AppendU16(eocd, 0);

    std::ofstream out{path, std::ios::binary};
    BOOST_REQUIRE(out);
    out << locals << centrals << eocd;
}

void WriteStoredZip64(const fs::path& path, const std::vector<std::pair<std::string, std::string>>& files)
{
    const auto [locals, centrals] = BuildStoredZipMembers(files);
    std::string zip64_eocd{"PK\x06\x06"};
    AppendU64(zip64_eocd, 44);
    AppendU16(zip64_eocd, 45);
    AppendU16(zip64_eocd, 45);
    AppendU32(zip64_eocd, 0);
    AppendU32(zip64_eocd, 0);
    AppendU64(zip64_eocd, files.size());
    AppendU64(zip64_eocd, files.size());
    AppendU64(zip64_eocd, centrals.size());
    AppendU64(zip64_eocd, locals.size());

    std::string locator{"PK\x06\x07"};
    AppendU32(locator, 0);
    AppendU64(locator, locals.size() + centrals.size());
    AppendU32(locator, 1);

    std::string eocd{"PK\x05\x06"};
    AppendU16(eocd, 0xffff);
    AppendU16(eocd, 0xffff);
    AppendU16(eocd, 0xffff);
    AppendU16(eocd, 0xffff);
    AppendU32(eocd, 0xffffffff);
    AppendU32(eocd, 0xffffffff);
    AppendU16(eocd, 0);

    std::ofstream out{path, std::ios::binary};
    BOOST_REQUIRE(out);
    out << locals << centrals << zip64_eocd << locator << eocd;
}

// Classic EOCD (disk=0) but central-directory sizes are ZIP64 sentinels, with
// the real sizes in extra 0x0001 after another extra block (as Python can emit).
void WriteStoredZipWithZip64Extra(const fs::path& path, const std::vector<std::pair<std::string, std::string>>& files)
{
    std::string locals;
    std::string centrals;
    uint32_t offset = 0;
    for (const auto& [name, data] : files) {
        const uint32_t crc = Crc32(data);
        const uint32_t size = static_cast<uint32_t>(data.size());
        std::string local{"PK\x03\x04"};
        AppendU16(local, 45);
        AppendU16(local, 0);
        AppendU16(local, 0);
        AppendU16(local, 0);
        AppendU16(local, 0);
        AppendU32(local, crc);
        AppendU32(local, size);
        AppendU32(local, size);
        AppendU16(local, static_cast<uint16_t>(name.size()));
        AppendU16(local, 0);
        local += name;
        local += data;

        std::string extra;
        AppendU16(extra, 0x5455); // dummy UT extra, so ZIP64 is not the first block
        AppendU16(extra, 1);
        extra.push_back(0);
        AppendU16(extra, 0x0001);
        AppendU16(extra, 16);
        AppendU64(extra, size);
        AppendU64(extra, size);

        std::string central{"PK\x01\x02"};
        AppendU16(central, 45);
        AppendU16(central, 45);
        AppendU16(central, 0);
        AppendU16(central, 0);
        AppendU16(central, 0);
        AppendU16(central, 0);
        AppendU32(central, crc);
        AppendU32(central, 0xffffffff);
        AppendU32(central, 0xffffffff);
        AppendU16(central, static_cast<uint16_t>(name.size()));
        AppendU16(central, static_cast<uint16_t>(extra.size()));
        AppendU16(central, 0);
        AppendU16(central, 0);
        AppendU16(central, 0);
        AppendU32(central, 0);
        AppendU32(central, offset);
        central += name;
        central += extra;

        offset += static_cast<uint32_t>(local.size());
        locals += local;
        centrals += central;
    }

    std::string eocd{"PK\x05\x06"};
    AppendU16(eocd, 0);
    AppendU16(eocd, 0);
    AppendU16(eocd, static_cast<uint16_t>(files.size()));
    AppendU16(eocd, static_cast<uint16_t>(files.size()));
    AppendU32(eocd, static_cast<uint32_t>(centrals.size()));
    AppendU32(eocd, static_cast<uint32_t>(locals.size()));
    AppendU16(eocd, 0);

    std::ofstream out{path, std::ios::binary};
    BOOST_REQUIRE(out);
    out << locals << centrals << eocd;
}

} // namespace

BOOST_AUTO_TEST_CASE(zip_extract_package_layout)
{
    const fs::path zip_path = m_path_root / "pkg.zip";
    WriteStoredZip(zip_path, {
        {"blocks/blk00000.dat", "blk"},
        {"chainstate/CURRENT", "CURRENT"},
        {"bitcoinpurity-package.json", "{}"},
        {"__MACOSX/ignored", "skip-me"},
    });

    std::string error;
    const auto entries = ZipListEntries(zip_path, error);
    BOOST_REQUIRE(entries);
    BOOST_CHECK_EQUAL(entries->size(), 4U);

    const fs::path dest = m_path_root / "extracted";
    BOOST_CHECK(ZipExtractTo(zip_path, dest, 0, [](std::string_view name) {
        return name.starts_with("__MACOSX/") || name.starts_with("._") || name.find("/._") != std::string_view::npos;
    }, error));
    BOOST_CHECK(fs::exists(dest / "blocks" / "blk00000.dat"));
    BOOST_CHECK(fs::exists(dest / "chainstate" / "CURRENT"));
    BOOST_CHECK(fs::exists(dest / "bitcoinpurity-package.json"));
    BOOST_CHECK(!fs::exists(dest / "__MACOSX"));
}

BOOST_AUTO_TEST_CASE(zip_extract_strips_wrapper_and_rejects_zip_slip)
{
    const fs::path wrapped = m_path_root / "wrapped.zip";
    WriteStoredZip(wrapped, {
        {"pkg/blocks/blk00000.dat", "blk"},
        {"pkg/chainstate/CURRENT", "CURRENT"},
    });
    std::string error;
    const fs::path dest = m_path_root / "stripped";
    BOOST_CHECK(ZipExtractTo(wrapped, dest, /*strip_components=*/1, {}, error));
    BOOST_CHECK(fs::exists(dest / "blocks" / "blk00000.dat"));
    BOOST_CHECK(fs::exists(dest / "chainstate" / "CURRENT"));

    const fs::path slip = m_path_root / "slip.zip";
    WriteStoredZip(slip, {{"../evil.txt", "nope"}});
    const fs::path slip_dest = m_path_root / "slip-out";
    BOOST_CHECK(!ZipExtractTo(slip, slip_dest, 0, {}, error));
}

BOOST_AUTO_TEST_CASE(zip_extract_deflated_entries)
{
    // Minimal ZIP_DEFLATED archive with blocks/ and chainstate/ files.
    static const unsigned char deflated_zip[] = {
        0x50,0x4b,0x03,0x04,0x14,0x00,0x00,0x00,0x08,0x00,0x62,0xa1,0x21,0x5d,0x27,0x5a,
        0x3a,0xa7,0x05,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x62,0x6c,
        0x6f,0x63,0x6b,0x73,0x2f,0x62,0x6c,0x6b,0x30,0x30,0x30,0x30,0x30,0x2e,0x64,0x61,
        0x74,0x4b,0xca,0xc9,0x06,0x00,0x50,0x4b,0x03,0x04,0x14,0x00,0x00,0x00,0x08,0x00,
        0x62,0xa1,0x21,0x5d,0x11,0xca,0xb6,0xe3,0x09,0x00,0x00,0x00,0x07,0x00,0x00,0x00,
        0x12,0x00,0x00,0x00,0x63,0x68,0x61,0x69,0x6e,0x73,0x74,0x61,0x74,0x65,0x2f,0x43,
        0x55,0x52,0x52,0x45,0x4e,0x54,0x73,0x0e,0x0d,0x0a,0x72,0xf5,0x0b,0x01,0x00,0x50,
        0x4b,0x01,0x02,0x14,0x03,0x14,0x00,0x00,0x00,0x08,0x00,0x62,0xa1,0x21,0x5d,0x27,
        0x5a,0x3a,0xa7,0x05,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x01,0x00,0x00,0x00,0x00,0x62,0x6c,0x6f,
        0x63,0x6b,0x73,0x2f,0x62,0x6c,0x6b,0x30,0x30,0x30,0x30,0x30,0x2e,0x64,0x61,0x74,
        0x50,0x4b,0x01,0x02,0x14,0x03,0x14,0x00,0x00,0x00,0x08,0x00,0x62,0xa1,0x21,0x5d,
        0x11,0xca,0xb6,0xe3,0x09,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x12,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x01,0x36,0x00,0x00,0x00,0x63,0x68,
        0x61,0x69,0x6e,0x73,0x74,0x61,0x74,0x65,0x2f,0x43,0x55,0x52,0x52,0x45,0x4e,0x54,
        0x50,0x4b,0x05,0x06,0x00,0x00,0x00,0x00,0x02,0x00,0x02,0x00,0x81,0x00,0x00,0x00,
        0x6f,0x00,0x00,0x00,0x00,0x00
    };
    const fs::path zip_path = m_path_root / "deflated.zip";
    {
        std::ofstream out{zip_path, std::ios::binary};
        BOOST_REQUIRE(out);
        out.write(reinterpret_cast<const char*>(deflated_zip), sizeof(deflated_zip));
    }

    std::string error;
    const fs::path dest = m_path_root / "deflated-out";
    BOOST_CHECK(ZipExtractTo(zip_path, dest, 0, {}, error));
    BOOST_CHECK(fs::exists(dest / "blocks" / "blk00000.dat"));
    BOOST_CHECK(fs::exists(dest / "chainstate" / "CURRENT"));
}

BOOST_AUTO_TEST_CASE(zip_extract_zip64_eocd)
{
    const fs::path zip_path = m_path_root / "zip64.zip";
    WriteStoredZip64(zip_path, {
        {"blocks/blk00000.dat", "blk"},
        {"chainstate/CURRENT", "CURRENT"},
    });
    std::string error;
    const fs::path dest = m_path_root / "zip64-out";
    BOOST_CHECK_MESSAGE(ZipExtractTo(zip_path, dest, 0, {}, error), error);
    BOOST_CHECK(fs::exists(dest / "blocks" / "blk00000.dat"));
    BOOST_CHECK(fs::exists(dest / "chainstate" / "CURRENT"));
}

BOOST_AUTO_TEST_CASE(zip_extract_data_descriptor_flag)
{
    const fs::path zip_path = m_path_root / "descriptor.zip";
    WriteStoredZip(zip_path, {
        {"blocks/blk00000.dat", "blk"},
        {"chainstate/CURRENT", "CURRENT"},
    }, /*flags=*/0x0008);
    std::string error;
    const fs::path dest = m_path_root / "descriptor-out";
    BOOST_CHECK_MESSAGE(ZipExtractTo(zip_path, dest, 0, {}, error), error);
    BOOST_CHECK(fs::exists(dest / "blocks" / "blk00000.dat"));
    BOOST_CHECK(fs::exists(dest / "chainstate" / "CURRENT"));
}

BOOST_AUTO_TEST_CASE(zip_extract_zip64_extra_after_other_extra)
{
    const fs::path zip_path = m_path_root / "zip64-extra.zip";
    WriteStoredZipWithZip64Extra(zip_path, {
        {"blocks/blk00000.dat", "blk"},
        {"chainstate/CURRENT", "CURRENT"},
    });
    std::string error;
    const fs::path dest = m_path_root / "zip64-extra-out";
    BOOST_CHECK_MESSAGE(ZipExtractTo(zip_path, dest, 0, {}, error), error);
    BOOST_CHECK(fs::exists(dest / "blocks" / "blk00000.dat"));
    BOOST_CHECK(fs::exists(dest / "chainstate" / "CURRENT"));
}

BOOST_AUTO_TEST_SUITE_END()
