// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/merkle.h>
#include <consensus/sharepool_hash.h>
#include <key.h>
#include <kernel/chainparams.h>
#include <pow.h>
#include <pubkey.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <versionbits.h>

#include <algorithm>
#include <array>
#include <map>
#include <memory>
#include <stdexcept>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {
using namespace sharepool;
namespace ho = sharepool::hashonly;

std::vector<unsigned char> Payout(unsigned char fill)
{
    std::vector<unsigned char> script{OP_0, 20};
    script.insert(script.end(), 20, fill);
    return script;
}

bool ProofLess(const uint256& a, const uint256& b)
{
    return UintToArith256(a) < UintToArith256(b);
}

struct HashFixture : BasicTestingSetup {
    static constexpr CAmount REWARD{100003};
    Consensus::Params consensus{CChainParams::RegTest({})->GetConsensus()};
    std::array<CBlockIndex, 6> indexes;
    std::array<uint256, 6> hashes;
    CKey key;
    std::map<uint256, std::shared_ptr<const ho::Snapshot>> snapshots;
    size_t native_checks{0};

    HashFixture()
    {
        consensus.hashGenesisBlock = uint256{uint8_t{1}};
        consensus.SharePoolHeight = 1;
        consensus.SharePoolHashOnly = true;
        consensus.Blake2bHeight = 1;
        // Public unit-vector key only; service/functional tests use fresh native keys.
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

    Envelope Owner(uint32_t height = 1, unsigned char script = 0x61)
    {
        Envelope envelope;
        envelope.version = ho::VERSION;
        envelope.genesis = consensus.hashGenesisBlock;
        envelope.rules = ho::RulesHash();
        envelope.height = height;
        envelope.native_parent = hashes.at(height - 1);
        envelope.pool = uint256{uint8_t{3}};
        const XOnlyPubKey pubkey{key.GetPubKey()};
        std::copy(pubkey.begin(), pubkey.end(), envelope.owner.begin());
        envelope.payout_script = Payout(script);
        return envelope;
    }

    Signature Sign(const Envelope& envelope)
    {
        Signature signature{};
        if (!key.SignSchnorr(ho::OwnerHash(envelope), signature, nullptr, {})) throw std::runtime_error("fixture signing failed");
        return signature;
    }

    ho::Snapshot Empty(uint32_t height = 1, unsigned char script = 0x61)
    {
        ho::Snapshot snapshot;
        snapshot.binding = Owner(height, script);
        snapshot.authorization = Sign(snapshot.binding);
        snapshot.payouts = ho::CalculatePayouts(snapshot, REWARD);
        return snapshot;
    }

    CBlock Block(const ho::Snapshot& snapshot)
    {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript{} << int64_t{snapshot.binding.height} << OP_0;
        coinbase.vout = snapshot.payouts;
        CBlock block;
        block.m_header_v2 = true;
        block.nVersion = VERSIONBITS_TOP_BITS;
        block.m_height = snapshot.binding.height;
        block.hashPrevBlock = snapshot.binding.native_parent;
        block.nTime = indexes.at(snapshot.binding.height - 1).nTime + 1;
        block.nBits = GetNextWorkRequired(&indexes.at(snapshot.binding.height - 1), &block, consensus);
        block.m_txcount = 1;
        block.vtx = {MakeTransactionRef(std::move(coinbase))};
        block.hashMerkleRoot = BlockMerkleRoot(block);
        block.m_mm_rhs = ho::SnapshotHash(snapshot);
        snapshots[block.m_mm_rhs] = std::make_shared<const ho::Snapshot>(snapshot);
        return block;
    }

    ho::TemplateRecord Record(const CBlock& block)
    {
        ho::TemplateRecord record;
        record.id = ho::TemplateId(block);
        VectorWriter{record.block, 0} << TX_WITH_WITNESS(block);
        return record;
    }

    Share Proof(const CBlock& origin, const ho::Snapshot& snapshot, uint32_t start)
    {
        Share share;
        share.header = origin.GetBlockHeader();
        share.origin = snapshot.binding;
        share.authorization = snapshot.authorization;
        for (uint32_t nonce{start}; nonce < start + 256; ++nonce) {
            share.header.nNonce = nonce;
            if (UintToArith256(share.header.GetHash()) <= arith_uint256{}.SetCompact(SHARE_BITS)) return share;
        }
        throw std::runtime_error("bounded fixture PoW failed");
    }

    ho::Snapshot WithShares(size_t count = 100)
    {
        const auto initial = Empty();
        const auto origin = Block(initial);
        auto snapshot = Empty();
        snapshot.templates.push_back(Record(origin));
        uint32_t nonce{1};
        for (size_t i{0}; i < count; ++i) {
            auto proof = Proof(origin, initial, nonce);
            nonce = proof.header.nNonce + 1;
            snapshot.shares.push_back(std::move(proof));
        }
        std::sort(snapshot.shares.begin(), snapshot.shares.end(), [](const auto& a, const auto& b) {
            return ProofLess(a.header.GetHash(), b.header.GetHash());
        });
        for (const auto& share : snapshot.shares) snapshot.post_state.push_back({1, share.header.GetHash()});
        snapshot.payouts = ho::CalculatePayouts(snapshot, REWARD);
        return snapshot;
    }

    ho::Lookup Lookup()
    {
        return [this](const uint256& hash) -> std::shared_ptr<const ho::Snapshot> {
            const auto found = snapshots.find(hash);
            return found == snapshots.end() ? nullptr : found->second;
        };
    }

    ho::ValidateOrigin Native()
    {
        return [this](const CBlock& block, const CBlockIndex* parent) {
            ++native_checks;
            if (!parent || block.hashPrevBlock != parent->GetBlockHash() || BlockMerkleRoot(block) != block.hashMerkleRoot) {
                return ho::Result::Invalid("fixture-body");
            }
            return ho::Result::Valid(REWARD);
        };
    }

    ho::Result Check(const CBlock& block, std::optional<CAmount> reward = REWARD)
    {
        return ho::CheckSnapshot(block, &indexes.at(block.m_height - 1), consensus, Lookup(), Native(), reward);
    }

    void Reason(const ho::Result& result, const std::string& suffix)
    {
        BOOST_CHECK(result.status == ho::Status::Invalid);
        BOOST_CHECK_EQUAL(result.reason, "bad-sharepool-hash-" + suffix);
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(sharepool_hash_tests, HashFixture)

BOOST_AUTO_TEST_CASE(independent_hash_and_wire_vectors)
{
    // Independently generated with Python hashlib + struct, including each NUL.
    BOOST_CHECK_EQUAL(ho::RulesHash().GetHex(), "88e35125fdb4bdac12fa4ffbbb608944b916103805396b4878d1dc9fb35c9ee4");
    auto snapshot = Empty();
    snapshot.binding.native_parent = uint256{uint8_t{2}};
    snapshot.authorization.fill(0);
    snapshot.payouts = ho::CalculatePayouts(snapshot, 5000000000);
    BOOST_CHECK_EQUAL(ho::OwnerHash(snapshot.binding).GetHex(), "8a692eaf034d7c2f86072d9f8d257fc9734e7a33828a4215e44708d7132c9205");
    const auto bytes = ho::EncodeSnapshot(snapshot);
    BOOST_CHECK_EQUAL(bytes.size(), 383);
    BOOST_CHECK_EQUAL(ho::SnapshotHash(snapshot).GetHex(), "3e91bd1c05e2e869ee8e39235de4fa5be3bfbcb12eff48f7a531b203fb5aa762");
    BOOST_CHECK(ho::SnapshotHash(bytes) == ho::SnapshotHash(snapshot));
    BOOST_CHECK(ho::EncodeSnapshot(ho::DecodeSnapshot(bytes)) == bytes);
    snapshot.post_state.push_back({1, uint256{uint8_t{7}}});
    BOOST_CHECK(ho::SnapshotHash(snapshot) != ho::SnapshotHash(bytes));
    snapshot = ho::DecodeSnapshot(bytes);
    snapshot.payouts[0].nValue--;
    BOOST_CHECK(ho::SnapshotHash(snapshot) != ho::SnapshotHash(bytes));
}

BOOST_AUTO_TEST_CASE(one_hundred_proofs_and_nonce_normalization)
{
    auto snapshot = WithShares();
    const auto bytes = ho::EncodeSnapshot(snapshot);
    const auto decoded = ho::DecodeSnapshot(bytes);
    BOOST_CHECK_EQUAL(decoded.shares.size(), 100);
    BOOST_CHECK(ho::EncodeSnapshot(decoded) == bytes);
    auto block = Block(snapshot);
    const auto result = Check(block);
    BOOST_CHECK_MESSAGE(result.IsValid(), result.reason);
    BOOST_CHECK_EQUAL(native_checks, 1); // Same exact origin body is checked once.
    auto nonce = snapshot.shares.front().header;
    nonce.nNonce++;
    nonce.m_nonce2++;
    nonce.m_nonce3++;
    nonce.m_extranonce.begin()[0] = 7;
    nonce.m_time_offset++;
    BOOST_CHECK(ho::TemplateId(nonce) == ho::TemplateId(snapshot.shares.front().header));
    BOOST_CHECK(nonce.GetHash() != snapshot.shares.front().header.GetHash());
    nonce.hashMerkleRoot = uint256{uint8_t{8}};
    BOOST_CHECK(ho::TemplateId(nonce) != ho::TemplateId(snapshot.shares.front().header));
}

BOOST_AUTO_TEST_CASE(missing_data_is_distinct_from_invalidity)
{
    const auto snapshot = WithShares(2);
    const auto block = Block(snapshot);
    const auto current = snapshots.at(block.m_mm_rhs);
    snapshots.erase(block.m_mm_rhs);
    auto result = Check(block);
    BOOST_CHECK(result.IsMissing());
    BOOST_REQUIRE_EQUAL(result.missing.size(), 1);
    BOOST_CHECK(result.missing[0] == block.m_mm_rhs);
    snapshots[block.m_mm_rhs] = current;
    const auto origin_hash = snapshot.shares[0].header.m_mm_rhs;
    snapshots.erase(origin_hash);
    result = Check(block);
    BOOST_CHECK(result.IsMissing());
    BOOST_REQUIRE_EQUAL(result.missing.size(), 1);
    BOOST_CHECK(result.missing[0] == origin_hash);
    // A local lookup that returns the wrong preimage cannot mark this block bad.
    snapshots[origin_hash] = current;
    result = Check(block);
    BOOST_CHECK(result.IsMissing());
    BOOST_CHECK(result.missing[0] == origin_hash);
    const auto malformed = ho::CheckSnapshot(block, &indexes[0], consensus,
        [](const uint256&) -> std::shared_ptr<const ho::Snapshot> { throw ho::MalformedSnapshot("authenticated malformed bytes"); }, Native(), REWARD);
    Reason(malformed, "snapshot-encoding");
}

BOOST_AUTO_TEST_CASE(known_empty_preimage_is_invalid_without_requesting_data)
{
    const auto hash = ho::SnapshotHash(Span<const unsigned char>{});
    BOOST_CHECK_EQUAL(hash.GetHex(), "0aae2d6c69aa5791a10e4ec19490d7b17816c18ac7c17803aa1afdd2099b7b77");
    BOOST_CHECK_THROW(ho::DecodeSnapshot(Span<const unsigned char>{}), std::ios_base::failure);
    auto block = Block(Empty());
    block.m_mm_rhs = hash;
    size_t lookups{0};
    const auto result = ho::CheckSnapshot(block, &indexes[0], consensus,
        [&](const uint256&) -> std::shared_ptr<const ho::Snapshot> { ++lookups; return nullptr; }, Native(), REWARD);
    Reason(result, "snapshot-encoding");
    BOOST_CHECK_EQUAL(lookups, 0);
}

BOOST_AUTO_TEST_CASE(current_owner_reserved_roots_and_reward)
{
    auto snapshot = Empty();
    Reason(Check(Block(snapshot), REWARD + 1), "reward");
    snapshot.authorization[0] ^= 1;
    Reason(Check(Block(snapshot)), "owner");
    snapshot = Empty();
    snapshot.binding.shares_root = uint256{uint8_t{7}};
    Reason(Check(Block(snapshot)), "reserved-roots");
    BOOST_CHECK_THROW(ho::DecodeSnapshot(ho::EncodeSnapshot(snapshot)), std::ios_base::failure);
    snapshot = Empty();
    snapshot.binding.version = 1;
    Reason(Check(Block(snapshot)), "version");
    auto block = Block(Empty());
    consensus.SharePoolHashOnly = false;
    Reason(Check(block), "inactive");
}

BOOST_AUTO_TEST_CASE(share_target_authorization_binding_and_full_origin)
{
    const auto initial = Empty();
    const auto origin = Block(initial);
    auto share = Proof(origin, initial, 1);
    const auto check = [&](const Share& value, const CBlock& body) {
        return ho::CheckShareProof(value, body, &indexes[0], origin.nTime, consensus, Lookup(), Native());
    };
    BOOST_CHECK(check(share, origin).IsValid());
    share.authorization[0] ^= 1;
    Reason(check(share, origin), "share-authorization");
    share.authorization = initial.authorization;
    while (UintToArith256(share.header.GetHash()) <= arith_uint256{}.SetCompact(SHARE_BITS)) ++share.header.nNonce;
    Reason(check(share, origin), "share-target");
    share = Proof(origin, initial, 1);
    share.origin.pool = uint256{uint8_t{4}};
    share.authorization = Sign(share.origin);
    Reason(check(share, origin), "share-binding");
    share = Proof(origin, initial, 1);
    auto wrong = origin;
    CMutableTransaction changed{*wrong.vtx[0]};
    changed.vout[0].nValue--;
    wrong.vtx[0] = MakeTransactionRef(changed);
    Reason(check(share, wrong), "template-encoding");
    wrong = origin;
    wrong.nNonce = 1;
    Reason(check(share, wrong), "template-encoding");
}

BOOST_AUTO_TEST_CASE(unused_full_templates_also_require_native_validation)
{
    const auto origin = Block(Empty());
    auto snapshot = Empty(1, 0x62);
    snapshot.templates.push_back(Record(origin));
    const auto block = Block(snapshot);
    size_t calls{0};
    const auto result = ho::CheckSnapshot(block, &indexes[0], consensus, Lookup(),
        [&](const CBlock&, const CBlockIndex*) { ++calls; return ho::Result::Invalid("bad-txns-inputs-missingorspent"); }, REWARD);
    Reason(result, "origin-body: bad-txns-inputs-missingorspent");
    BOOST_CHECK_EQUAL(calls, 1);
    const auto no_reward = ho::CheckSnapshot(block, &indexes[0], consensus, Lookup(),
        [](const CBlock&, const CBlockIndex*) { return ho::Result::Valid(); }, REWARD);
    Reason(no_reward, "origin-reward");
}

BOOST_AUTO_TEST_CASE(origin_memo_includes_exact_witness_body)
{
    // Both base bodies have identical normalized headers/txids; only witness
    // bytes differ. Nested snapshots can refer to both under the same ID.
    auto good = Block(Empty());
    CMutableTransaction coinbase{*good.vtx[0]};
    coinbase.vin[0].scriptWitness.stack = {std::vector<unsigned char>(32)};
    good.vtx[0] = MakeTransactionRef(coinbase);
    auto bad = good;
    coinbase.vin[0].scriptWitness.stack[0][0] = 1;
    bad.vtx[0] = MakeTransactionRef(coinbase);
    BOOST_CHECK(ho::TemplateId(good) == ho::TemplateId(bad));
    BOOST_CHECK(Record(good).block != Record(bad).block);
    auto good_snapshot = Empty(1, 0x62);
    good_snapshot.templates.push_back(Record(good));
    const auto good_wrapper = Block(good_snapshot);
    auto bad_snapshot = Empty(1, 0x63);
    bad_snapshot.templates.push_back(Record(bad));
    auto bad_wrapper = Block(bad_snapshot);
    // Establish deterministic traversal: valid body caches first, bad second.
    while (!(ho::TemplateId(good_wrapper) < ho::TemplateId(bad_wrapper))) ++bad_wrapper.nTime;
    auto final = Empty(1, 0x64);
    final.templates = {Record(good_wrapper), Record(bad_wrapper)};
    const auto block = Block(final);
    size_t good_checks{0}, bad_checks{0};
    const auto result = ho::CheckSnapshot(block, &indexes[0], consensus, Lookup(),
        [&](const CBlock& origin, const CBlockIndex*) {
            if (ho::TemplateId(origin) == ho::TemplateId(good)) {
                if (origin.vtx[0]->vin[0].scriptWitness.stack[0][0] == 1) {
                    ++bad_checks;
                    return ho::Result::Invalid("fixture-bad-witness");
                }
                ++good_checks;
            }
            return ho::Result::Valid(REWARD);
        }, REWARD);
    Reason(result, "origin-body: fixture-bad-witness");
    BOOST_CHECK_EQUAL(good_checks, 1);
    BOOST_CHECK_EQUAL(bad_checks, 1);
}

BOOST_AUTO_TEST_CASE(recommitting_does_not_authorize_wrong_payouts)
{
    auto snapshot = WithShares(3);
    const auto other_script = Payout(0x62);
    snapshot.payouts[0].scriptPubKey = CScript{other_script.begin(), other_script.end()};
    Reason(Check(Block(snapshot)), "payouts");
    snapshot = WithShares(3);
    snapshot.payouts[0].nValue--;
    Reason(Check(Block(snapshot)), "reward");
    snapshot = WithShares(3);
    auto block = Block(snapshot);
    CMutableTransaction coinbase{*block.vtx[0]};
    coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << std::vector<unsigned char>{'S', 'P', 'N', '1'});
    block.vtx[0] = MakeTransactionRef(coinbase);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    Reason(Check(block), "coinbase-layout");
    // The sole optional non-monetary output is the final exact witness carrier.
    coinbase.vout.pop_back();
    std::vector<unsigned char> witness{OP_RETURN, 0x24, 0xaa, 0x21, 0xa9, 0xed};
    witness.resize(38);
    coinbase.vout.emplace_back(0, CScript{witness.begin(), witness.end()});
    block.vtx[0] = MakeTransactionRef(coinbase);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    BOOST_CHECK(Check(block).IsValid()); // Native BIP141 validation is caller-owned.
}

BOOST_AUTO_TEST_CASE(parent_state_repeat_payment_and_late_proof)
{
    const auto first = WithShares(3);
    const auto parent = Block(first);
    indexes[1].m_mm_rhs = parent.m_mm_rhs;
    auto next = Empty(2);
    next.post_state = first.post_state;
    BOOST_CHECK(Check(Block(next)).IsValid());
    next.templates = first.templates;
    next.shares.push_back(first.shares[0]);
    Reason(Check(Block(next)), "repeat-payment");
    next = Empty(2);
    next.post_state = first.post_state;
    next.post_state.pop_back();
    Reason(Check(Block(next)), "state");
    next = Empty(2);
    next.post_state = first.post_state;
    next.templates = first.templates;
    const auto initial = Empty();
    const auto origin = Block(initial);
    next.shares.push_back(Proof(origin, initial, 10000));
    next.post_state.push_back({1, next.shares[0].header.GetHash()});
    std::sort(next.post_state.begin(), next.post_state.end(), [](const auto& a, const auto& b) { return ProofLess(a.proof_id, b.proof_id); });
    next.payouts = ho::CalculatePayouts(next, REWARD);
    BOOST_CHECK(Check(Block(next)).IsValid());
    // The earlier committed snapshot is unchanged when the late proof is added.
    BOOST_CHECK(ho::SnapshotHash(first) == parent.m_mm_rhs);
    snapshots.erase(parent.m_mm_rhs);
    const auto result = Check(Block(next));
    BOOST_CHECK(result.IsMissing());
    BOOST_CHECK(std::find(result.missing.begin(), result.missing.end(), parent.m_mm_rhs) != result.missing.end());
}

BOOST_AUTO_TEST_CASE(canonical_order_and_duplicate_proofs)
{
    auto snapshot = WithShares(3);
    std::swap(snapshot.shares[0], snapshot.shares[1]);
    BOOST_CHECK_THROW(ho::DecodeSnapshot(ho::EncodeSnapshot(snapshot)), std::ios_base::failure);
    Reason(Check(Block(snapshot)), "share-order");
    snapshot = WithShares(3);
    snapshot.shares[1] = snapshot.shares[0];
    Reason(Check(Block(snapshot)), "share-order");
    snapshot = WithShares(3);
    std::swap(snapshot.post_state[0], snapshot.post_state[1]);
    BOOST_CHECK_THROW(ho::DecodeSnapshot(ho::EncodeSnapshot(snapshot)), std::ios_base::failure);
    Reason(Check(Block(snapshot)), "state-order");
    snapshot = WithShares(3);
    snapshot.templates.push_back(snapshot.templates[0]);
    BOOST_CHECK_THROW(ho::DecodeSnapshot(ho::EncodeSnapshot(snapshot)), std::ios_base::failure);
    Reason(Check(Block(snapshot)), "template-order");
    snapshot = WithShares(3);
    snapshot.templates.clear();
    Reason(Check(Block(snapshot)), "share-template-missing");
    // Distinguish numeric proof ordering from serialized-byte template ordering.
    const auto one = ArithToUint256(arith_uint256{1});
    const auto two_fifty_six = ArithToUint256(arith_uint256{256});
    BOOST_CHECK(ProofLess(one, two_fifty_six));
    BOOST_CHECK(two_fifty_six < one);
}

BOOST_AUTO_TEST_CASE(bounded_canonical_parser)
{
    const auto bytes = ho::EncodeSnapshot(Empty());
    for (size_t length{0}; length < bytes.size(); ++length) {
        BOOST_CHECK_THROW(ho::DecodeSnapshot(Span{bytes}.first(length)), std::ios_base::failure);
    }
    auto bad = bytes;
    bad.push_back(0);
    BOOST_CHECK_THROW(ho::DecodeSnapshot(bad), std::ios_base::failure);
    // Template count follows the 284-byte binding and 64-byte authorization.
    bad = bytes;
    bad[348] = 0xfd;
    bad.insert(bad.begin() + 349, {0, 0});
    BOOST_CHECK_THROW(ho::DecodeSnapshot(bad), std::ios_base::failure);
    for (const size_t offset : {348, 349, 350, 351}) {
        bad = bytes;
        bad[offset] = 0xfe;
        bad.insert(bad.begin() + offset + 1, {0xff, 0xff, 0xff, 0x01});
        BOOST_CHECK_THROW(ho::DecodeSnapshot(bad), std::ios_base::failure);
    }
    BOOST_CHECK_THROW(ho::DecodeSnapshot(std::vector<unsigned char>(ho::MAX_SNAPSHOT_BYTES + 1)), std::ios_base::failure);
    auto snapshot = WithShares(1);
    snapshot.templates[0].block.resize(ho::MAX_TEMPLATE_BYTES + 1);
    BOOST_CHECK_THROW(ho::EncodeSnapshot(snapshot), std::ios_base::failure);
    snapshot = WithShares(1);
    // Nested native tx count requests must be rejected before vector allocation.
    auto& raw = snapshot.templates[0].block;
    raw[164] = 0xfe;
    raw.insert(raw.begin() + 165, {0xff, 0xff, 0xff, 0x01});
    BOOST_CHECK_THROW(ho::DecodeSnapshot(ho::EncodeSnapshot(snapshot)), std::ios_base::failure);
    Reason(Check(Block(snapshot)), "template-encoding");
}

BOOST_AUTO_TEST_CASE(overflow_safe_payout_arithmetic_without_32_share_quota)
{
    auto snapshot = Empty();
    snapshot.shares.resize(10000);
    for (auto& share : snapshot.shares) share.origin.payout_script = Payout(0x61);
    auto payouts = ho::CalculatePayouts(snapshot, MAX_MONEY);
    BOOST_REQUIRE_EQUAL(payouts.size(), 1);
    BOOST_CHECK_EQUAL(payouts[0].nValue, MAX_MONEY);
    // reward*count would overflow uint64_t; decomposition retains exact total.
    for (size_t i{0}; i < 3333; ++i) snapshot.shares[i].origin.payout_script = Payout(0x62);
    payouts = ho::CalculatePayouts(snapshot, MAX_MONEY - 1);
    BOOST_REQUIRE_EQUAL(payouts.size(), 2);
    BOOST_CHECK_EQUAL(payouts[0].nValue + payouts[1].nValue, MAX_MONEY - 1);
    snapshot.shares.resize(2);
    snapshot.shares[0].origin.payout_script = Payout(0x61);
    snapshot.shares[1].origin.payout_script = Payout(0x62);
    payouts = ho::CalculatePayouts(snapshot, 3);
    BOOST_CHECK_EQUAL(payouts[0].nValue, 2);
    BOOST_CHECK_EQUAL(payouts[1].nValue, 1);
    BOOST_CHECK_THROW(ho::CalculatePayouts(snapshot, MAX_MONEY + 1), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(dependency_depth_is_a_distinct_bounded_failure)
{
    const auto block = Block(Empty());
    Reason(ho::CheckSnapshot(block, &indexes[0], consensus, Lookup(), Native(), REWARD, ho::MAX_DEPENDENCY_DEPTH + 1), "dependency-depth");
    BOOST_CHECK(ho::CheckSnapshot(block, &indexes[0], consensus, Lookup(), Native(), REWARD, ho::MAX_DEPENDENCY_DEPTH).IsValid());
}

BOOST_AUTO_TEST_CASE(dependency_depth_cannot_be_bypassed_by_a_shorter_memoized_path)
{
    auto origin = Block(Empty());
    CBlock short_path;
    for (uint32_t i{1}; i <= ho::MAX_DEPENDENCY_DEPTH; ++i) {
        auto snapshot = Empty();
        snapshot.templates.push_back(Record(origin));
        origin = Block(snapshot);
        if (i == 1) short_path = origin;
    }
    // This chain itself uses precisely64 dependency edges and is permitted.
    BOOST_CHECK(Check(origin).IsValid());
    // First validate/cache a shorter route to a shared subtree. Its appearance
    // at depth64 on the second route must still recurse to the forbidden65th.
    while (!(ho::TemplateId(short_path) < ho::TemplateId(origin))) ++origin.nTime;
    auto snapshot = Empty(1, 0x62);
    snapshot.templates = {Record(short_path), Record(origin)};
    Reason(Check(Block(snapshot)), "dependency-depth");
}

BOOST_AUTO_TEST_CASE(unique_dependency_bytes_are_bounded_across_recursion)
{
    // Five individually bounded snapshots exceed64MiB in aggregate. Their
    // synthetic carried states are only structural byte-budget fixtures: the
    // dependency bound must fire before the deepest semantic state comparison.
    auto snapshot = Empty();
    snapshot.post_state.resize(ho::MAX_DEPENDENCY_BYTES / 5 / 36 + 1);
    for (size_t i{0}; i < snapshot.post_state.size(); ++i) {
        snapshot.post_state[i] = {1, ArithToUint256(arith_uint256{static_cast<uint64_t>(i + 1)})};
    }
    auto origin = Block(snapshot);
    for (size_t i{1}; i < 5; ++i) {
        snapshot.templates = {Record(origin)};
        origin = Block(snapshot);
    }
    Reason(Check(origin), "dependency-bytes");
}

BOOST_AUTO_TEST_SUITE_END()
