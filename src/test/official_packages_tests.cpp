// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/official_packages.h>

#include <chainparams.h>
#include <key.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <string>

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
        "https://downloads.bitcoinpurity.org/mainnet/pkg.zip", OfficialPackageTrustPolicy::STRICT));
    BOOST_CHECK(!IsOfficialDownloadUriAllowed(
        "http://downloads.bitcoinpurity.org/mainnet/pkg.zip", OfficialPackageTrustPolicy::STRICT));
    BOOST_CHECK(!IsOfficialDownloadUriAllowed(
        "https://evil.example/mainnet/pkg.zip", OfficialPackageTrustPolicy::STRICT));
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
        unsigned_json, "test", OfficialPackageTrustPolicy::STRICT);
    BOOST_CHECK(packages.empty());

    const auto local_packages = ParseOfficialDataPackagesFromJson(
        unsigned_json, "test", OfficialPackageTrustPolicy::LOCAL);
    BOOST_CHECK_EQUAL(local_packages.size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
