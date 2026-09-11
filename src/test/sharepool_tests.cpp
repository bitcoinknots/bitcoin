// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/merkle.h>
#include <consensus/sharepool.h>
#include <consensus/validation.h>
#include <init.h>
#include <key.h>
#include <kernel/chainparams.h>
#include <pow.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <versionbits.h>

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {
using namespace sharepool;

std::vector<unsigned char> Payout(unsigned char fill)
{
    std::vector<unsigned char> script{OP_0, 20};
    script.insert(script.end(), 20, fill);
    return script;
}

struct NativeFixture : BasicTestingSetup {
    Consensus::Params consensus{CChainParams::RegTest({})->GetConsensus()};
    std::array<CBlockIndex, 6> indexes;
    std::array<uint256, 6> hashes;
    CKey key;

    NativeFixture()
    {
        consensus.hashGenesisBlock = uint256{uint8_t{1}};
        consensus.SharePoolHeight = 1;
        consensus.Blake2bHeight = 1;
        std::array<unsigned char, 32> secret{};
        secret.back() = 1;
        key.Set(secret.begin(), secret.end(), true);
        for (size_t i{0}; i < indexes.size(); ++i) {
            hashes[i] = uint256{static_cast<uint8_t>(i + 1)};
            indexes[i].phashBlock = &hashes[i];
            indexes[i].nHeight = i;
            indexes[i].nTime = 1000 + i * 600;
            indexes[i].nBits = SHARE_BITS;
            indexes[i].m_header_v2 = i > 0;
            if (i) {
                indexes[i].pprev = &indexes[i - 1];
                indexes[i].BuildSkip();
            }
        }
    }

    Envelope Owner(uint32_t height, unsigned char script = 0x61)
    {
        Envelope envelope;
        envelope.genesis = consensus.hashGenesisBlock;
        envelope.rules = RulesHash();
        envelope.height = height;
        envelope.native_parent = hashes[height - 1];
        envelope.pool = uint256{uint8_t{3}};
        const XOnlyPubKey pubkey{key.GetPubKey()};
        std::copy(pubkey.begin(), pubkey.end(), envelope.owner.begin());
        envelope.payout_script = Payout(script);
        return envelope;
    }

    Signature Sign(const Envelope& envelope)
    {
        Signature signature{};
        if (!key.SignSchnorr(OwnerHash(envelope), signature, nullptr, {})) throw std::runtime_error("fixture signing failed");
        return signature;
    }

    Share Proof(uint32_t height = 1, unsigned char script = 0x61, uint32_t start = 0)
    {
        Share share;
        share.origin = Owner(height, script);
        share.authorization = Sign(share.origin);
        auto& header = share.header;
        header.m_header_v2 = true;
        header.nVersion = VERSIONBITS_TOP_BITS;
        header.m_height = height;
        header.hashPrevBlock = hashes[height - 1];
        header.hashMerkleRoot = uint256{uint8_t{7}};
        header.m_txcount = 1;
        header.nTime = indexes[height - 1].nTime + 1;
        header.nBits = GetNextWorkRequired(&indexes[height - 1], &header, consensus);
        header.m_mm_rhs = EnvelopeHash(share.origin);
        for (uint32_t nonce = start; nonce < start + 256; ++nonce) {
            header.nNonce = nonce;
            if (UintToArith256(header.GetHash()) <= arith_uint256{}.SetCompact(SHARE_BITS)) return share;
        }
        throw std::runtime_error("bounded share mining failed");
    }

    CBlock Block(Manifest& manifest, CAmount reward = 100003)
    {
        auto& current = manifest.current;
        std::sort(manifest.shares.begin(), manifest.shares.end(), [](const auto& a, const auto& b) {
            return UintToArith256(a.header.GetHash()) < UintToArith256(b.header.GetHash());
        });
        std::vector<StateEntry> next;
        for (const auto& entry : manifest.parent_state) {
            if (int64_t{entry.origin_height} >= int64_t{current.height} - MAX_SHARE_AGE) next.push_back(entry);
        }
        for (const auto& share : manifest.shares) next.push_back({uint32_t(share.header.m_height), share.header.GetHash()});
        std::sort(next.begin(), next.end(), [](const auto& a, const auto& b) {
            return UintToArith256(a.proof_id) < UintToArith256(b.proof_id);
        });
        current.state_root = StateRoot(next);
        current.shares_root = SharesRoot(manifest.shares);
        const auto payouts = CalculatePayouts(manifest, reward);
        current.payouts_root = PayoutsRoot(payouts);
        manifest.authorization = Sign(current);
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript{} << int64_t{current.height} << OP_0;
        coinbase.vout = payouts;
        const auto carriers = CarrierOutputs(EncodeManifest(manifest));
        coinbase.vout.insert(coinbase.vout.end(), carriers.begin(), carriers.end());
        CBlock block;
        block.m_header_v2 = true;
        block.nVersion = VERSIONBITS_TOP_BITS;
        block.m_height = current.height;
        block.hashPrevBlock = current.native_parent;
        block.nTime = indexes[current.height - 1].nTime + 1;
        block.nBits = GetNextWorkRequired(&indexes[current.height - 1], &block, consensus);
        block.m_txcount = 1;
        block.vtx = {MakeTransactionRef(std::move(coinbase))};
        block.hashMerkleRoot = BlockMerkleRoot(block);
        block.m_mm_rhs = EnvelopeHash(current);
        return block;
    }

    bool Check(const CBlock& block, CAmount reward = 100003)
    {
        BlockValidationState state;
        return CheckSharePoolBlock(block, state, consensus, &indexes[block.m_height - 1], reward);
    }

    Manifest First()
    {
        Manifest manifest;
        manifest.current = Owner(1);
        return manifest;
    }

    Manifest WithParent(uint32_t height, std::vector<StateEntry> parent_state)
    {
        Manifest manifest;
        manifest.current = Owner(height);
        manifest.has_parent = 1;
        manifest.parent = Owner(height - 1);
        manifest.parent_state = std::move(parent_state);
        manifest.parent.state_root = StateRoot(manifest.parent_state);
        indexes[height - 1].m_mm_rhs = EnvelopeHash(manifest.parent);
        return manifest;
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(sharepool_tests, NativeFixture)

BOOST_AUTO_TEST_CASE(independent_wire_and_hash_vectors)
{
    BOOST_CHECK_EQUAL(RulesHash().GetHex(), "068afe304d17019542089f3b2f00d4998cd522983b0571e32f0bacb9d4c44af1");
    auto manifest = First();
    manifest.current.native_parent = uint256{uint8_t{2}};
    manifest.current.payouts_root = PayoutsRoot(CalculatePayouts(manifest, 5000000000));
    manifest.authorization = Sign(manifest.current);
    BOOST_CHECK_EQUAL(EnvelopeHash(manifest.current).GetHex(), "7ff30080210857ee529629bf56d2fe98f2ac70db11852ed3ef95474ad458789a");
    const auto bytes = EncodeManifest(manifest);
    BOOST_CHECK_EQUAL(bytes.size(), 351);
    BOOST_CHECK(EncodeManifest(DecodeManifest(bytes)) == bytes);
    for (const auto& output : CarrierOutputs(bytes)) BOOST_CHECK_LE(output.scriptPubKey.size(), 83);
}

BOOST_AUTO_TEST_CASE(bounded_canonical_parser)
{
    const auto bytes = EncodeManifest(First());
    for (const auto& [offset, value] : std::array<std::pair<size_t, unsigned char>, 4>{{{165, 35}, {348, 2}, {349, 129}, {350, 33}}}) {
        auto bad = bytes;
        bad[offset] = value;
        BOOST_CHECK_THROW(DecodeManifest(bad), std::ios_base::failure);
    }
    auto trailing = bytes;
    trailing.push_back(0);
    BOOST_CHECK_THROW(DecodeManifest(trailing), std::ios_base::failure);
    auto nonminimal = bytes;
    nonminimal[349] = 0xfd;
    nonminimal.insert(nonminimal.begin() + 350, {0, 0});
    BOOST_CHECK_THROW(DecodeManifest(nonminimal), std::ios_base::failure);
    BOOST_CHECK_THROW(DecodeManifest(std::vector<unsigned char>(MAX_MANIFEST + 1)), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(exact_payouts_and_current_authorization)
{
    auto manifest = First();
    auto block = Block(manifest);
    BOOST_CHECK(Check(block));
    BOOST_CHECK(!Check(block, 100004));
    CMutableTransaction wrong{*block.vtx[0]};
    wrong.vout[0].nValue -= 1;
    block.vtx[0] = MakeTransactionRef(wrong);
    BOOST_CHECK(!Check(block));
    block = Block(manifest);
    block.m_mm_rhs = uint256{uint8_t{7}};
    BOOST_CHECK(!Check(block));
    block = Block(manifest);
    block.m_flags = 1;
    BOOST_CHECK(!Check(block));
    block = Block(manifest);
    wrong = CMutableTransaction{*block.vtx[0]};
    auto encoded = EncodeManifest(manifest);
    encoded[284] ^= 1;
    wrong.vout = CalculatePayouts(manifest, 100003);
    const auto carriers = CarrierOutputs(encoded);
    wrong.vout.insert(wrong.vout.end(), carriers.begin(), carriers.end());
    block.vtx[0] = MakeTransactionRef(wrong);
    BOOST_CHECK(!Check(block));
}

BOOST_AUTO_TEST_CASE(carrier_layout_is_exact)
{
    auto manifest = First();
    const auto block = Block(manifest);
    for (int mutation{0}; mutation < 5; ++mutation) {
        auto bad = block;
        CMutableTransaction coinbase{*bad.vtx[0]};
        if (mutation == 0) coinbase.vout[1].nValue = 1;
        if (mutation == 1) std::swap(coinbase.vout[1], coinbase.vout[2]);
        if (mutation == 2) coinbase.vout.push_back(coinbase.vout[0]);
        if (mutation == 3) coinbase.vout.pop_back();
        if (mutation == 4) coinbase.vout[1].scriptPubKey.push_back(OP_0);
        bad.vtx[0] = MakeTransactionRef(coinbase);
        BOOST_CHECK(!Check(bad));
    }
}

BOOST_AUTO_TEST_CASE(shares_use_native_pow_context_and_owner_binding)
{
    auto share = Proof();
    std::string error;
    BOOST_CHECK(CheckShare(share, &indexes[0], 1001, consensus, error));
    for (int mutation{0}; mutation < 6; ++mutation) {
        auto bad = share;
        if (mutation == 0) bad.origin.payout_script = Payout(0x62);
        if (mutation == 1) bad.header.hashPrevBlock = uint256{uint8_t{9}};
        if (mutation == 2) bad.header.nBits -= 1;
        if (mutation == 3) bad.header.nTime = 1000;
        if (mutation == 4) bad.authorization[0] ^= 1;
        if (mutation == 5) bad.header.m_flags = 1;
        BOOST_CHECK(!CheckShare(bad, &indexes[0], 1001, consensus, error));
    }
    auto high_hash = share;
    while (UintToArith256(high_hash.header.GetHash()) <= arith_uint256{}.SetCompact(SHARE_BITS)) ++high_hash.header.nNonce;
    BOOST_CHECK(!CheckShare(high_hash, &indexes[0], 1001, consensus, error));
}

BOOST_AUTO_TEST_CASE(proportional_rounding_aggregates_scripts)
{
    auto manifest = First();
    manifest.shares = {Proof(1, 0x61, 0), Proof(1, 0x61, 1000), Proof(1, 0x62, 2000)};
    auto block = Block(manifest);
    BOOST_REQUIRE(Check(block));
    BOOST_CHECK_EQUAL(block.vtx[0]->vout[0].nValue, 66669);
    BOOST_CHECK_EQUAL(block.vtx[0]->vout[1].nValue, 33334);
    const auto tiny = CalculatePayouts(manifest, 1);
    BOOST_CHECK_EQUAL(tiny[0].nValue, 1);
    BOOST_CHECK_EQUAL(tiny[1].nValue, 0);
    const auto zero = CalculatePayouts(manifest, 0);
    BOOST_CHECK_EQUAL(zero.size(), 2);
    BOOST_CHECK_EQUAL(zero[0].nValue, 0);
    BOOST_CHECK_THROW(CalculatePayouts(manifest, MAX_MONEY + 1), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(duplicates_and_parent_opening_are_consensus_bound)
{
    const auto share = Proof();
    auto manifest = First();
    manifest.shares = {share, share};
    BOOST_CHECK(!Check(Block(manifest)));
    manifest = WithParent(2, {{1, share.header.GetHash()}});
    manifest.shares = {share};
    BOOST_CHECK(!Check(Block(manifest)));
    manifest.shares.clear();
    auto valid = Block(manifest);
    BOOST_CHECK(Check(valid));
    indexes[1].m_mm_rhs = uint256{uint8_t{6}};
    BOOST_CHECK(!Check(valid));
}

BOOST_AUTO_TEST_CASE(exact_age_and_nullifier_expiry)
{
    const auto share = Proof();
    std::string error;
    BOOST_CHECK(CheckShare(share, &indexes[3], indexes[3].nTime + 1, consensus, error));
    BOOST_CHECK(!CheckShare(share, &indexes[4], indexes[4].nTime + 1, consensus, error));
    auto replay = WithParent(4, {{1, share.header.GetHash()}});
    replay.shares = {share};
    BOOST_CHECK(!Check(Block(replay)));
    auto expired = WithParent(5, {{1, share.header.GetHash()}});
    auto block = Block(expired);
    BOOST_CHECK(expired.current.state_root.IsNull());
    BOOST_CHECK(Check(block));
    expired.shares = {share};
    BOOST_CHECK(!Check(Block(expired)));
}

BOOST_AUTO_TEST_CASE(default_disabled_and_explicit_regtest_parameters)
{
    const auto check_disabled = [](const auto& params) {
        BOOST_CHECK_EQUAL(params->GetConsensus().SharePoolHeight, std::numeric_limits<int>::max());
    };
    check_disabled(CChainParams::Main());
    check_disabled(CChainParams::TestNet());
    check_disabled(CChainParams::TestNet4());
    check_disabled(CChainParams::SigNet({}));
    check_disabled(CChainParams::RegTest({}));
    Consensus::Params inactive = consensus;
    inactive.SharePoolHeight = std::numeric_limits<int>::max();
    BlockValidationState state;
    BOOST_CHECK(CheckSharePoolBlock(CBlock{}, state, inactive, &indexes[0]));
    CChainParams::RegTestOptions options;
    options.sharepool_height = 3;
    BOOST_CHECK_THROW(CChainParams::RegTest(options), std::runtime_error);
    options.activation_heights[Consensus::DEPLOYMENT_BLAKE2B] = 3;
    for (const int height : {-1, 0, 2, std::numeric_limits<int>::max()}) {
        options.sharepool_height = height;
        BOOST_CHECK_THROW(CChainParams::RegTest(options), std::runtime_error);
    }
    for (const int height : {3, 4}) {
        options.sharepool_height = height;
        BOOST_CHECK_EQUAL(CChainParams::RegTest(options)->GetConsensus().SharePoolHeight, height);
    }
}

BOOST_AUTO_TEST_CASE(help_defaults_do_not_reinterpret_test_activation)
{
    // Statistics registration still uses the global manager owned by this
    // fixture. Reuse it rather than registering those options twice globally.
    auto& args = *m_node.args;
    args.ClearArgs();
    SetupServerArgs(args);
    args.ForceSetArg("-sharepoolheight", "2");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::MAIN), std::runtime_error);
    args.ClearArgs();
    BOOST_CHECK_NO_THROW(SetupServerArgs(args));
}

BOOST_AUTO_TEST_SUITE_END()
