// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/merkle.h>
#include <consensus/sharepool_hash.h>
#include <hash.h>
#include <key.h>
#include <kernel/chainparams.h>
#include <kernel/cs_main.h>
#include <pow.h>
#include <pubkey.h>
#include <script/script.h>
#include <sharepool/hash_store.h>
#include <sharepool/hash_validation_cache.h>
#include <sharepool/tides_history_store.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <versionbits.h>

#include <algorithm>
#include <array>
#include <map>
#include <memory>
#include <new>
#include <stdexcept>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/multiprecision/cpp_int.hpp>

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

// Frozen pre-optimization serialization oracle. Deliberately sizes complete
// bodies and each table transaction independently; do not use resource helpers
// here, so component accounting and optimized traversal cannot agree by accident.
std::vector<unsigned char> OriginalSnapshotEncoding(const ho::Snapshot& snapshot)
{
    std::map<Wtxid, std::pair<CTransactionRef, uint32_t>> table;
    size_t expanded{0};
    for (const auto& record : snapshot.templates) {
        expanded += GetSerializeSize(TX_WITH_WITNESS(record.block));
        for (const auto& tx : record.block.vtx) table.try_emplace(tx->GetWitnessHash(), tx, 0);
    }
    BOOST_REQUIRE_LE(expanded, ho::MAX_EXPANDED_TEMPLATE_BYTES);
    uint32_t index{0};
    for (auto& [id, entry] : table) entry.second = index++;
    std::vector<unsigned char> bytes;
    VectorWriter writer{bytes, 0};
    writer << snapshot.binding << snapshot.authorization << snapshot.job_commitment;
    WriteCompactSize(writer, table.size());
    for (const auto& [id, entry] : table) {
        WriteCompactSize(writer, GetSerializeSize(TX_WITH_WITNESS(*entry.first)));
        writer << TX_WITH_WITNESS(*entry.first);
    }
    WriteCompactSize(writer, snapshot.templates.size());
    for (const auto& record : snapshot.templates) {
        writer << record.id << record.block.GetBlockHeader();
        WriteCompactSize(writer, record.block.vtx.size());
        for (const auto& tx : record.block.vtx) WriteCompactSize(writer, table.at(tx->GetWitnessHash()).second);
    }
    writer << snapshot.shares << snapshot.post_state << snapshot.payouts;
    if (snapshot.binding.version == ho::LEDGER_VERSION) writer << snapshot.pending << snapshot.settled << snapshot.certificates;
    if (snapshot.binding.version == ho::TIDES_VERSION) writer << snapshot.certificates << snapshot.history_head;
    return bytes;
}

size_t ComponentBytes(const ho::SnapshotResourceUsage& usage)
{
    return usage.binding_bytes + usage.transaction_table_bytes + usage.template_table_bytes + usage.job_table_bytes + usage.share_bytes + usage.state_bytes +
        usage.payout_bytes + usage.pending_bytes + usage.settled_bytes + usage.certificate_bytes + usage.history_bytes;
}

struct HashFixture : BasicTestingSetup {
    static constexpr CAmount REWARD{100003};
    Consensus::Params consensus{CChainParams::RegTest({})->GetConsensus()};
    std::array<CBlockIndex, 12> indexes;
    std::array<uint256, 12> hashes;
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
        envelope.version = ho::ProfileVersion(consensus);
        envelope.genesis = consensus.hashGenesisBlock;
        envelope.rules = ho::RulesHash(envelope.version);
        envelope.height = height;
        envelope.native_parent = hashes.at(height - 1);
        envelope.pool = uint256{uint8_t{3}};
        const XOnlyPubKey pubkey{key.GetPubKey()};
        std::copy(pubkey.begin(), pubkey.end(), envelope.owner.begin());
        envelope.payout_script = Payout(script);
        return envelope;
    }

    Signature Sign(const ho::Snapshot& snapshot)
    {
        Signature signature{};
        if (!key.SignSchnorr(ho::OwnerHash(snapshot), signature, nullptr, {})) throw std::runtime_error("fixture signing failed");
        return signature;
    }

    ho::Snapshot Empty(uint32_t height = 1, unsigned char script = 0x61)
    {
        ho::Snapshot snapshot;
        snapshot.binding = Owner(height, script);
        snapshot.payouts = ho::CalculatePayouts(snapshot, REWARD);
        return snapshot;
    }

    CBlock Block(ho::Snapshot& snapshot)
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
        snapshot.job_commitment = ho::JobHash(block);
        snapshot.authorization = Sign(snapshot);
        block.m_mm_rhs = ho::SnapshotHash(snapshot);
        snapshots[block.m_mm_rhs] = std::make_shared<const ho::Snapshot>(snapshot);
        return block;
    }

    CBlock Block(ho::Snapshot&& snapshot) { return Block(snapshot); }

    void Reseal(CBlock& block)
    {
        auto snapshot = *snapshots.at(block.m_mm_rhs);
        snapshot.job_commitment = ho::JobHash(block);
        snapshot.authorization = Sign(snapshot);
        block.m_mm_rhs = ho::SnapshotHash(snapshot);
        snapshots[block.m_mm_rhs] = std::make_shared<const ho::Snapshot>(snapshot);
    }

    ho::TemplateRecord Record(const CBlock& block)
    {
        ho::TemplateRecord record;
        record.id = ho::TemplateId(block);
        record.block = block;
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

    Share AssignedProof(const CBlock& origin, const ho::Snapshot& snapshot, uint32_t start = 1)
    {
        Share share{origin.GetBlockHeader(), snapshot.binding, snapshot.authorization};
        const auto target = UintToArith256(ho::ShareTarget(share));
        for (uint32_t nonce{start}; nonce < start + 65536; ++nonce) {
            share.header.nNonce = nonce;
            if (!share.header.GetHash().IsNull() && UintToArith256(share.header.GetHash()) <= target) return share;
        }
        throw std::runtime_error("bounded assigned-work fixture PoW failed");
    }

    ho::Snapshot WithShares(size_t count = 100)
    {
        auto initial = Empty();
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

    void LedgerState(ho::Snapshot& snapshot)
    {
        const auto parent = snapshot.binding.height == uint32_t(consensus.SharePoolHeight) ? nullptr :
            snapshots.at(indexes.at(snapshot.binding.height - 1).m_mm_rhs).get();
        ho::ApplyLedgerState(snapshot, parent);
        snapshot.payouts = ho::CalculatePayouts(snapshot, REWARD);
    }

    void Anchor(const CBlock& block)
    {
        auto& index = indexes.at(block.m_height);
        hashes.at(block.m_height) = block.GetHash();
        index.m_mm_rhs = block.m_mm_rhs;
        index.nTime = block.nTime;
        index.nBits = block.nBits;
    }

    ho::Snapshot CompactEmpty(uint32_t height = 1, unsigned char script = 0x61)
    {
        ho::Snapshot snapshot;
        snapshot.binding = Owner(height, script);
        CompactState(snapshot);
        return snapshot;
    }

    void CompactState(ho::Snapshot& snapshot)
    {
        auto* previous = &indexes.at(snapshot.binding.height - 1);
        const auto state = ho::MaterializeTidesState(snapshot, previous, consensus, Lookup());
        BOOST_REQUIRE_MESSAGE(state.IsValid(), state.reason);
        CBlockHeader header;
        header.nTime = previous->nTime + 1;
        const auto payouts = ho::CalculateTidesPayouts(snapshot, previous, GetNextWorkRequired(previous, &header, consensus),
                                                     consensus, Lookup(), REWARD, snapshot.payouts);
        BOOST_REQUIRE_MESSAGE(payouts.IsValid(), payouts.reason);
    }

    CBlock CompactBlock(ho::Snapshot& snapshot)
    {
        const auto block = Block(snapshot);
        // Exercise the same empty derived-cache objects returned by the native
        // canonical archive, not pre-populated test-only state.
        snapshots[block.m_mm_rhs] = std::make_shared<const ho::Snapshot>(ho::DecodeSnapshot(ho::EncodeSnapshot(snapshot)));
        return block;
    }

    static void SortEvidence(ho::Snapshot& snapshot)
    {
        std::sort(snapshot.templates.begin(), snapshot.templates.end(), [](const auto& a, const auto& b) { return a.id < b.id; });
        std::sort(snapshot.shares.begin(), snapshot.shares.end(), [](const auto& a, const auto& b) {
            return ProofLess(a.header.GetHash(), b.header.GetHash());
        });
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
    BOOST_CHECK_EQUAL(ho::RulesHash().GetHex(), "2d8343cd857f5ea23b189a5db0c52ddc7923a5b96bed09e3624391da04d8e9c0");
    auto snapshot = Empty();
    snapshot.binding.native_parent = uint256{uint8_t{2}};
    snapshot.authorization.fill(0);
    snapshot.payouts = ho::CalculatePayouts(snapshot, 5000000000);
    BOOST_CHECK_EQUAL(ho::OwnerHash(snapshot).GetHex(), "4d63b169a940b811cb88e8021cf673d547296e9a11c280f121b2a4679c612dae");
    const auto bytes = ho::EncodeSnapshot(snapshot);
    BOOST_CHECK_EQUAL(bytes.size(), 416);
    BOOST_CHECK_EQUAL(ho::SnapshotHash(snapshot).GetHex(), "cf9e974afc17c767b79ad846d59c77d8e0fa3667f1386577d9d62b1a513badef");
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

BOOST_AUTO_TEST_CASE(prepared_codec_matches_original_wire_and_profile_hashes)
{
    auto snapshot = WithShares(3);
    CMutableTransaction shared;
    shared.vin.resize(1);
    shared.vin[0].prevout = COutPoint{Txid::FromUint256(uint256{uint8_t{123}}), 0};
    shared.vin[0].scriptWitness.stack = {{1, 2, 3}};
    shared.vout.emplace_back(1, CScript{} << OP_TRUE);
    const auto first = MakeTransactionRef(shared);
    shared.vin[0].scriptWitness.stack[0][0] = 9;
    const auto second = MakeTransactionRef(shared);
    BOOST_CHECK(first->GetHash() == second->GetHash());
    BOOST_CHECK(first->GetWitnessHash() != second->GetWitnessHash());
    // Cross the 252/253 CompactSize thresholds for table/template counts and
    // transaction indices, while retaining distinct witness-only tx bodies.
    const auto original = snapshot.templates.front().block;
    for (int i{0}; i < 260; ++i) {
        auto origin = original;
        CMutableTransaction coinbase{*origin.vtx.front()};
        coinbase.vin[0].scriptSig << int64_t{i + 100};
        origin.vtx = {MakeTransactionRef(std::move(coinbase)), i % 2 ? first : second};
        origin.m_txcount = origin.vtx.size();
        origin.hashMerkleRoot = BlockMerkleRoot(origin);
        snapshot.templates.push_back(Record(origin));
    }
    std::sort(snapshot.templates.begin(), snapshot.templates.end(), [](const auto& a, const auto& b) { return a.id < b.id; });
    for (const auto version : {ho::VERSION, ho::LEDGER_VERSION, ho::TIDES_VERSION}) {
        snapshot.binding.version = version;
        snapshot.binding.rules = ho::RulesHash(version);
        snapshot.pending.clear();
        snapshot.settled.clear();
        snapshot.certificates.clear();
        snapshot.history_head.SetNull();
        if (version == ho::LEDGER_VERSION) {
            snapshot.pending.push_back({1, 1, uint256{uint8_t{5}}, snapshot.binding.pool, SHARE_BITS, Payout(0x61)});
            snapshot.settled.push_back({1, 1, uint256{uint8_t{6}}, snapshot.binding.pool, SHARE_BITS, Payout(0x62)});
        }
        if (version != ho::VERSION) snapshot.certificates.push_back({1, hashes[0], uint256{uint8_t{7}}, uint256{uint8_t{8}}});
        if (version == ho::TIDES_VERSION) snapshot.history_head = uint256{uint8_t{9}};
        const auto expected = OriginalSnapshotEncoding(snapshot);
        BOOST_CHECK(ho::EncodeSnapshot(snapshot) == expected);
        BOOST_CHECK(ho::ProfileSnapshotHash(snapshot, version) == ho::ProfileSnapshotHash(expected, version));
        BOOST_CHECK(ho::EncodeSnapshot(ho::DecodeSnapshot(expected)) == expected);
        const auto usage = ho::MeasureSnapshotResources(snapshot);
        BOOST_CHECK_EQUAL(usage.encoded_bytes, expected.size());
        BOOST_CHECK_EQUAL(ComponentBytes(usage), expected.size());
        BOOST_CHECK_EQUAL(usage.templates, 261);
        BOOST_CHECK_EQUAL(usage.unique_transactions, 263);
        BOOST_CHECK_EQUAL(usage.transaction_references, 521);
        BOOST_CHECK_EQUAL(usage.pending_bytes, version == ho::LEDGER_VERSION ? GetSerializeSize(snapshot.pending) : 0);
        BOOST_CHECK_EQUAL(usage.history_bytes, version == ho::TIDES_VERSION ? 32 : 0);
        auto unsigned_snapshot = snapshot;
        unsigned_snapshot.authorization.fill(0);
        const auto unsigned_raw = OriginalSnapshotEncoding(unsigned_snapshot);
        HashWriter contents;
        static constexpr char v4[]{"SharePool/contents/v4"};
        static constexpr char v5[]{"SharePool/contents/v5"};
        static constexpr char v6[]{"SharePool/contents/v6"};
        contents.write(AsBytes(version == ho::TIDES_VERSION ? Span{v6} : version == ho::LEDGER_VERSION ? Span{v5} : Span{v4}));
        contents.write(AsBytes(Span{unsigned_raw}));
        BOOST_CHECK(ho::SnapshotContentsHash(snapshot) == contents.GetHash());
    }
}

BOOST_AUTO_TEST_CASE(resource_measurement_never_reuses_mutated_object_metadata)
{
    auto snapshot = WithShares(1);
    const auto before = ho::MeasureSnapshotResources(snapshot);
    const auto original_hash = ho::SnapshotHash(snapshot);
    auto& origin = snapshot.templates.front().block;
    CMutableTransaction coinbase{*origin.vtx.front()};
    coinbase.vin[0].scriptWitness.stack = {std::vector<unsigned char>(32, 1)};
    origin.vtx.front() = MakeTransactionRef(std::move(coinbase));
    const auto after = ho::MeasureSnapshotResources(snapshot);
    BOOST_CHECK_GT(after.unique_transaction_bytes, before.unique_transaction_bytes);
    BOOST_CHECK_GT(after.expanded_template_bytes, before.expanded_template_bytes);
    BOOST_CHECK(ho::SnapshotHash(snapshot) != original_hash);
    BOOST_CHECK(ho::EncodeSnapshot(snapshot) == OriginalSnapshotEncoding(snapshot));
    snapshot.payouts[0].scriptPubKey.push_back(OP_TRUE);
    BOOST_CHECK_EQUAL(ho::MeasureSnapshotResources(snapshot).encoded_bytes, after.encoded_bytes + 1);
    snapshot.templates.front().block.vtx.front().reset();
    BOOST_CHECK_THROW(ho::MeasureSnapshotResources(snapshot), std::ios_base::failure);
    BOOST_CHECK_THROW(ho::EncodeSnapshot(snapshot), std::ios_base::failure);
    BOOST_CHECK_THROW(ho::SnapshotHash(snapshot), std::ios_base::failure);
    snapshot = WithShares(1);
    snapshot.shares.resize(ho::MAX_SNAPSHOT_BYTES / 512 + 1, snapshot.shares.front());
    BOOST_CHECK_THROW(ho::MeasureSnapshotResources(snapshot), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shared_references_keep_the_original_global_reference_budget)
{
    auto snapshot = Empty();
    auto origin = Block(Empty());
    origin.vtx.resize(20'000, origin.vtx.front());
    origin.m_txcount = origin.vtx.size();
    // Structural resource fixture: duplicate coinbases are not native-valid.
    snapshot.templates.resize(100, Record(origin));
    const auto usage = ho::MeasureSnapshotResources(snapshot);
    BOOST_CHECK_EQUAL(usage.transaction_references, ho::MAX_TEMPLATE_TX_REFERENCES);
    BOOST_CHECK_EQUAL(usage.unique_transactions, 1);
    BOOST_CHECK_EQUAL(usage.expanded_template_bytes, 100 * GetSerializeSize(TX_WITH_WITNESS(origin)));
    BOOST_CHECK_EQUAL(usage.encoded_bytes, ho::EncodeSnapshot(snapshot).size());
    snapshot.templates.back().block.vtx.push_back(origin.vtx.front());
    BOOST_CHECK_THROW(ho::MeasureSnapshotResources(snapshot), std::ios_base::failure);
    BOOST_CHECK_THROW(ho::EncodeSnapshot(snapshot), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shared_payload_keeps_exact_individual_and_expanded_byte_limits)
{
    auto origin = Block(Empty());
    CMutableTransaction transaction;
    transaction.vin.resize(1);
    transaction.vin[0].prevout = COutPoint{Txid::FromUint256(uint256{uint8_t{123}}), 0};
    CScript script;
    script.resize(3'850'000);
    transaction.vout.emplace_back(1, script);
    origin.vtx.push_back(MakeTransactionRef(transaction));
    const auto padding = ho::MAX_TEMPLATE_BYTES - GetSerializeSize(TX_WITH_WITNESS(origin));
    transaction.vout[0].scriptPubKey.resize(script.size() + padding);
    origin.vtx.back() = MakeTransactionRef(transaction);
    origin.m_txcount = origin.vtx.size();
    origin.hashMerkleRoot = BlockMerkleRoot(origin);
    BOOST_CHECK_EQUAL(GetSerializeSize(TX_WITH_WITNESS(origin)), ho::MAX_TEMPLATE_BYTES);
    auto snapshot = Empty();
    snapshot.templates.push_back(Record(origin));
    const auto one = ho::MeasureSnapshotResources(snapshot);
    BOOST_CHECK_EQUAL(one.expanded_template_bytes, ho::MAX_TEMPLATE_BYTES);
    BOOST_CHECK(ho::EncodeSnapshot(ho::DecodeSnapshot(ho::EncodeSnapshot(snapshot))) == OriginalSnapshotEncoding(snapshot));
    transaction.vout[0].scriptPubKey.push_back(OP_0);
    snapshot.templates[0].block.vtx.back() = MakeTransactionRef(transaction);
    BOOST_CHECK_THROW(ho::MeasureSnapshotResources(snapshot), std::ios_base::failure);
    snapshot.templates[0] = Record(origin);
    const auto maximum = ho::MAX_EXPANDED_TEMPLATE_BYTES / ho::MAX_TEMPLATE_BYTES;
    snapshot.templates.resize(maximum, Record(origin));
    const auto usage = ho::MeasureSnapshotResources(snapshot);
    BOOST_CHECK_EQUAL(usage.unique_transaction_bytes, one.unique_transaction_bytes);
    BOOST_CHECK_EQUAL(usage.expanded_template_bytes, maximum * size_t{ho::MAX_TEMPLATE_BYTES});
    BOOST_CHECK_LT(usage.encoded_bytes, ho::MAX_SNAPSHOT_BYTES);
    snapshot.templates.push_back(Record(origin));
    BOOST_CHECK_THROW(ho::MeasureSnapshotResources(snapshot), std::ios_base::failure);
    BOOST_CHECK_THROW(ho::EncodeSnapshot(snapshot), std::ios_base::failure);
    BOOST_CHECK_THROW(ho::SnapshotContentsHash(snapshot), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(deduplicated_large_templates_preserve_complete_transaction_bytes)
{
    // A wire fixture: script/UTXO validity is intentionally outside this codec
    // test. Every full body is3.85MB;100 copies share immutable transaction refs.
    auto opening = Empty();
    auto origin = Block(opening);
    CMutableTransaction transaction;
    transaction.vin.resize(1);
    transaction.vin[0].prevout = COutPoint{Txid::FromUint256(uint256{uint8_t{123}}), 0};
    CScript large_script;
    large_script.resize(3'850'000);
    transaction.vout.emplace_back(1, large_script);
    origin.vtx.push_back(MakeTransactionRef(std::move(transaction)));
    origin.m_txcount = origin.vtx.size();
    origin.hashMerkleRoot = BlockMerkleRoot(origin);
    auto snapshot = Empty();
    for (size_t i{0}; i < 100; ++i) {
        ++origin.nTime;
        snapshot.templates.push_back(Record(origin));
    }
    std::sort(snapshot.templates.begin(), snapshot.templates.end(), [](const auto& a, const auto& b) { return a.id < b.id; });
    const auto bytes = ho::EncodeSnapshot(snapshot);
    BOOST_CHECK_LT(bytes.size(), 3'900'000);
    const auto decoded = ho::DecodeSnapshot(bytes);
    BOOST_REQUIRE_EQUAL(decoded.templates.size(), 100);
    for (const auto& record : decoded.templates) {
        BOOST_CHECK(record.block.vtx[1] == decoded.templates[0].block.vtx[1]);
        BOOST_CHECK_GT(GetSerializeSize(TX_WITH_WITNESS(record.block)), 3'850'000);
        BOOST_CHECK(record.id == ho::TemplateId(record.block));
        BOOST_CHECK(BlockMerkleRoot(record.block) == record.block.hashMerkleRoot);
    }
    BOOST_CHECK(ho::EncodeSnapshot(decoded) == bytes);
    const auto database = m_path_root / "hash-template-dedup";
    size_t stored_bytes{0};
    {
        HashSnapshotStore store{database};
        LOCK(cs_main);
        for (const auto& record : decoded.templates) store.RememberTemplate(record.block);
        stored_bytes = store.TemplateBytes();
        BOOST_CHECK_LT(stored_bytes, 3'900'000);
        BOOST_CHECK_EQUAL(store.TemplateCount(), 100);
        for (const auto& record : decoded.templates) store.RememberTemplate(record.block);
        BOOST_CHECK_EQUAL(store.TemplateBytes(), stored_bytes); // Atomic idempotent records.
    }
    {
        HashSnapshotStore restored{database};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(restored.TemplateBytes(), stored_bytes);
        BOOST_CHECK_EQUAL(restored.TemplateCount(), 100);
        const auto first = restored.Template(decoded.templates[0].id);
        BOOST_REQUIRE(first);
        for (const auto& record : decoded.templates) {
            const auto full = restored.Template(record.id);
            BOOST_REQUIRE(full);
            BOOST_CHECK(ho::JobHash(*full) == ho::JobHash(record.block));
            BOOST_CHECK(full->vtx[1] == first->vtx[1]);
        }
    }
    for (size_t i{100}; i < 140; ++i) {
        ++origin.nTime;
        snapshot.templates.push_back(Record(origin));
    }
    BOOST_CHECK_THROW(ho::EncodeSnapshot(snapshot), std::ios_base::failure);
    auto null_transaction = Empty();
    origin.vtx[0].reset();
    null_transaction.templates.push_back(Record(origin));
    BOOST_CHECK_THROW(ho::EncodeSnapshot(null_transaction), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(unsigned_preparation_never_exempts_nested_owner_authorizations)
{
    auto snapshot = Empty();
    auto block = Block(snapshot);
    snapshot.authorization.fill(0);
    block.m_mm_rhs = ho::SnapshotHash(snapshot);
    snapshots[block.m_mm_rhs] = std::make_shared<const ho::Snapshot>(snapshot);
    Reason(Check(block), "owner");
    const auto prepared = ho::CheckSnapshot(block, &indexes[0], consensus, Lookup(), Native(), REWARD, 0, true);
    BOOST_CHECK_MESSAGE(prepared.IsValid(), prepared.reason);
    auto child = Empty();
    child.templates.push_back(Record(block));
    auto child_block = Block(child);
    child.authorization.fill(0);
    child_block.m_mm_rhs = ho::SnapshotHash(child);
    snapshots[child_block.m_mm_rhs] = std::make_shared<const ho::Snapshot>(child);
    Reason(ho::CheckSnapshot(child_block, &indexes[0], consensus, Lookup(), Native(), REWARD, 0, true), "owner");
}

BOOST_AUTO_TEST_CASE(missing_data_is_distinct_from_invalidity)
{
    auto snapshot = WithShares(2);
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
    BOOST_CHECK_EQUAL(hash.GetHex(), "4bce13ffe53d9519f745352981f2c4d6d3d2b748c5eb8beb2edd0a95b820fcda");
    BOOST_CHECK_THROW(ho::DecodeSnapshot(Span<const unsigned char>{}), std::ios_base::failure);
    auto block = Block(Empty());
    block.m_mm_rhs = hash;
    size_t lookups{0};
    const auto result = ho::CheckSnapshot(block, &indexes[0], consensus,
        [&](const uint256&) -> std::shared_ptr<const ho::Snapshot> { ++lookups; return nullptr; }, Native(), REWARD);
    Reason(result, "snapshot-encoding");
    BOOST_CHECK_EQUAL(lookups, 0);
}

BOOST_AUTO_TEST_CASE(local_callback_failures_are_unavailable_not_invalid_encoding)
{
    const auto block = Block(WithShares(1));
    const ho::Lookup unavailable = [](const uint256&) -> std::shared_ptr<const ho::Snapshot> {
        throw std::bad_alloc{};
    };
    BOOST_CHECK(ho::CheckSnapshot(block, &indexes[0], consensus, unavailable, Native(), REWARD).IsMissing());
    BOOST_CHECK(ho::CheckMiningJob(block, &indexes[0], consensus, unavailable, Native(), REWARD).IsMissing());
    const ho::ValidateOrigin native_failure = [](const CBlock&, const CBlockIndex*) -> ho::Result {
        throw std::runtime_error("local native validation unavailable");
    };
    BOOST_CHECK(ho::CheckSnapshot(block, &indexes[0], consensus, Lookup(), native_failure, REWARD).IsMissing());
    BOOST_CHECK(ho::CheckMiningJob(block, &indexes[0], consensus, Lookup(), native_failure, REWARD).IsMissing());
    // Authenticated bad bytes are still an explicit consensus encoding failure.
    const ho::Lookup malformed = [](const uint256&) -> std::shared_ptr<const ho::Snapshot> {
        throw ho::MalformedSnapshot("authenticated malformed bytes");
    };
    Reason(ho::CheckSnapshot(block, &indexes[0], consensus, malformed, Native(), REWARD), "snapshot-encoding");
}

BOOST_AUTO_TEST_CASE(current_owner_reserved_roots_and_reward)
{
    auto snapshot = Empty();
    Reason(Check(Block(snapshot), REWARD + 1), "reward");
    auto invalid_owner = Block(snapshot);
    snapshot.authorization[0] ^= 1;
    invalid_owner.m_mm_rhs = ho::SnapshotHash(snapshot);
    snapshots[invalid_owner.m_mm_rhs] = std::make_shared<const ho::Snapshot>(snapshot);
    Reason(Check(invalid_owner), "owner");
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
    auto initial = Empty();
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
    Reseal(good);
    auto bad = good;
    coinbase.vin[0].scriptWitness.stack[0][0] = 1;
    bad.vtx[0] = MakeTransactionRef(coinbase);
    BOOST_CHECK(ho::TemplateId(good) == ho::TemplateId(bad));
    BOOST_CHECK(ho::JobHash(good) != ho::JobHash(bad));
    auto good_snapshot = Empty(1, 0x62);
    good_snapshot.templates.push_back(Record(good));
    const auto good_wrapper = Block(good_snapshot);
    auto bad_snapshot = Empty(1, 0x63);
    bad_snapshot.templates.push_back(Record(bad));
    auto bad_wrapper = Block(bad_snapshot);
    // Establish deterministic traversal: valid body caches first, bad second.
    while (!(ho::TemplateId(good_wrapper) < ho::TemplateId(bad_wrapper))) { ++bad_wrapper.nTime; Reseal(bad_wrapper); }
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
    Reason(result, "job-commitment");
    BOOST_CHECK_EQUAL(good_checks, 1);
    BOOST_CHECK_EQUAL(bad_checks, 0); // Exact witness attestation fails before scripts.
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
    Reseal(block);
    Reason(Check(block), "coinbase-layout");
    // The sole optional non-monetary output is the final exact witness carrier.
    coinbase.vout.pop_back();
    std::vector<unsigned char> witness{OP_RETURN, 0x24, 0xaa, 0x21, 0xa9, 0xed};
    witness.resize(38);
    coinbase.vout.emplace_back(0, CScript{witness.begin(), witness.end()});
    block.vtx[0] = MakeTransactionRef(coinbase);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    Reseal(block);
    BOOST_CHECK(Check(block).IsValid()); // Native BIP141 validation is caller-owned.
}

BOOST_AUTO_TEST_CASE(parent_state_repeat_payment_and_late_proof)
{
    auto first = WithShares(3);
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
    auto initial = Empty();
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
    // Transaction table count follows the 284-byte binding, 64-byte signature and 32-byte job.
    bad = bytes;
    bad[380] = 0xfd;
    bad.insert(bad.begin() + 381, {0, 0});
    BOOST_CHECK_THROW(ho::DecodeSnapshot(bad), std::ios_base::failure);
    for (const size_t offset : {380, 381, 382, 383, 384}) {
        bad = bytes;
        bad[offset] = 0xfe;
        bad.insert(bad.begin() + offset + 1, {0xff, 0xff, 0xff, 0x01});
        BOOST_CHECK_THROW(ho::DecodeSnapshot(bad), std::ios_base::failure);
    }
    BOOST_CHECK_THROW(ho::DecodeSnapshot(std::vector<unsigned char>(ho::MAX_SNAPSHOT_BYTES + 1)), std::ios_base::failure);
    auto snapshot = WithShares(1);
    CMutableTransaction oversized{*snapshot.templates[0].block.vtx[0]};
    oversized.vin[0].scriptSig.resize(ho::MAX_TEMPLATE_BYTES + 1);
    snapshot.templates[0].block.vtx[0] = MakeTransactionRef(oversized);
    BOOST_CHECK_THROW(ho::EncodeSnapshot(snapshot), std::ios_base::failure);
    snapshot = WithShares(1);
    // A body's transaction count remains exact after table expansion.
    snapshot.templates[0].block.m_txcount++;
    snapshot.templates[0].id = ho::TemplateId(snapshot.templates[0].block);
    BOOST_CHECK_THROW(ho::DecodeSnapshot(ho::EncodeSnapshot(snapshot)), std::ios_base::failure);
    Reason(Check(Block(snapshot)), "template-encoding");
}

BOOST_AUTO_TEST_CASE(overflow_safe_payout_arithmetic_without_32_share_quota)
{
    auto snapshot = Empty();
    snapshot.shares.resize(10000);
    for (auto& share : snapshot.shares) { share.origin.payout_script = Payout(0x61); share.header.nBits = SHARE_BITS; }
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

BOOST_AUTO_TEST_CASE(worked_refresh_admission_reserves_future_settlement_depth)
{
    auto opening = Empty();
    auto origin = Block(opening);
    // Each edge is needed by genuine solved work from the preceding signed
    // template. Removing unworked inventory cannot shorten this chain.
    for (uint32_t depth{1}; depth < ho::MAX_DEPENDENCY_DEPTH; ++depth) {
        const auto proof = Proof(origin, opening, depth);
        auto next = Empty();
        next.templates = {Record(origin)};
        next.shares = {proof};
        next.post_state = {{proof.origin.height, proof.header.GetHash()}};
        next.payouts = ho::CalculatePayouts(next, REWARD);
        origin = Block(next);
        opening = next;
    }
    // A depth63 job leaves one edge for the settlement of its future proof.
    BOOST_REQUIRE(Check(origin).IsValid());
    BOOST_REQUIRE(ho::CheckMiningJob(origin, &indexes[0], consensus, Lookup(), Native(), REWARD).IsValid());
    const auto proof = Proof(origin, opening, 1000);
    BOOST_REQUIRE(ho::CheckShareProof(proof, origin, &indexes[0], origin.nTime,
                                      consensus, Lookup(), Native()).IsValid());
    auto settlement = Empty();
    settlement.templates = {Record(origin)};
    settlement.shares = {proof};
    settlement.post_state = {{proof.origin.height, proof.header.GetHash()}};
    settlement.payouts = ho::CalculatePayouts(settlement, REWARD);
    const auto boundary = Block(settlement);
    // This depth64 block remains consensus-valid and can pay the admitted work.
    // It must not be offered as a job that promises another payable proof.
    BOOST_REQUIRE(Check(boundary).IsValid());
    Reason(ho::CheckMiningJob(boundary, &indexes[0], consensus, Lookup(), Native(), REWARD), "dependency-depth");
    const auto unpayable = Proof(boundary, settlement, 2000);
    Reason(ho::CheckShareProof(unpayable, boundary, &indexes[0], boundary.nTime,
                               consensus, Lookup(), Native()), "dependency-depth");

    // Native preparation uses the same reservation while only its current
    // owner signature is absent. Origin signatures remain mandatory.
    auto unsigned_opening = opening;
    unsigned_opening.authorization.fill(0);
    auto unsigned_origin = origin;
    unsigned_origin.m_mm_rhs = ho::SnapshotHash(unsigned_opening);
    snapshots[unsigned_origin.m_mm_rhs] = std::make_shared<const ho::Snapshot>(unsigned_opening);
    BOOST_CHECK(ho::CheckMiningJob(unsigned_origin, &indexes[0], consensus, Lookup(), Native(), REWARD, true).IsValid());
    auto unsigned_settlement = settlement;
    unsigned_settlement.authorization.fill(0);
    auto unsigned_boundary = boundary;
    unsigned_boundary.m_mm_rhs = ho::SnapshotHash(unsigned_settlement);
    snapshots[unsigned_boundary.m_mm_rhs] = std::make_shared<const ho::Snapshot>(unsigned_settlement);
    Reason(ho::CheckMiningJob(unsigned_boundary, &indexes[0], consensus, Lookup(), Native(), REWARD, true), "dependency-depth");
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
    while (!(ho::TemplateId(short_path) < ho::TemplateId(origin))) { ++origin.nTime; Reseal(origin); }
    auto snapshot = Empty(1, 0x62);
    snapshot.templates = {Record(short_path), Record(origin)};
    Reason(Check(Block(snapshot)), "dependency-depth");
}

BOOST_AUTO_TEST_CASE(dense_dependency_dag_checks_each_exact_origin_once)
{
    constexpr size_t ORIGINS{60};
    std::vector<ho::TemplateRecord> records;
    for (size_t i{0}; i < ORIGINS; ++i) {
        auto snapshot = Empty();
        snapshot.templates = records; // Every job includes all earlier jobs.
        const auto block = Block(snapshot);
        records.push_back(Record(block));
        std::sort(records.begin(), records.end(), [](const auto& a, const auto& b) { return a.id < b.id; });
    }
    auto settlement = Empty(1, 0x62);
    settlement.templates = records;
    const auto block = Block(settlement);
    // The previous (body, absolute depth) memo performed 1,830 native checks
    // and 36,050 dependency-edge body hashes for this 60-origin graph.
    const auto checked = Check(block);
    BOOST_CHECK_MESSAGE(checked.IsValid(), checked.reason);
    BOOST_CHECK_EQUAL(native_checks, ORIGINS);

    // The longest route, not whichever route cached a node first, determines
    // validity. Exactly 64 edges remains valid; one additional edge fails.
    native_checks = 0;
    const auto boundary = ho::CheckSnapshot(block, &indexes[0], consensus, Lookup(), Native(),
                                           REWARD, ho::MAX_DEPENDENCY_DEPTH - ORIGINS);
    BOOST_CHECK_MESSAGE(boundary.IsValid(), boundary.reason);
    BOOST_CHECK_EQUAL(native_checks, ORIGINS);
    Reason(ho::CheckSnapshot(block, &indexes[0], consensus, Lookup(), Native(),
                            REWARD, ho::MAX_DEPENDENCY_DEPTH - ORIGINS + 1), "dependency-depth");
}

BOOST_AUTO_TEST_CASE(memoized_missing_origins_still_count_declared_dependency_edges)
{
    auto origin = Block(Empty());
    const auto unavailable_id = ho::TemplateId(origin);
    CBlock short_path;
    for (uint32_t i{1}; i <= ho::MAX_DEPENDENCY_DEPTH; ++i) {
        auto snapshot = Empty();
        snapshot.templates.push_back(Record(origin));
        origin = Block(snapshot);
        if (i == 1) short_path = origin;
    }
    // Cache the short subtree with a temporarily unavailable native child.
    // Its declared child still makes its intrinsic depth at least one.
    while (!(ho::TemplateId(short_path) < ho::TemplateId(origin))) { ++origin.nTime; Reseal(origin); }
    auto snapshot = Empty(1, 0x62);
    snapshot.templates = {Record(short_path), Record(origin)};
    const auto block = Block(snapshot);
    Reason(ho::CheckSnapshot(block, &indexes[0], consensus, Lookup(),
        [&](const CBlock& body, const CBlockIndex*) {
            if (ho::TemplateId(body) == unavailable_id) return ho::Result::Missing({}, "fixture-native-pending");
            return ho::Result::Valid(REWARD);
        }, REWARD), "dependency-depth");
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

BOOST_AUTO_TEST_CASE(deterministic_share_target_and_weighted_payouts)
{
    BOOST_CHECK(ho::ShareTarget(SHARE_BITS) == ArithToUint256(arith_uint256{}.SetCompact(SHARE_BITS)));
    BOOST_CHECK(ho::ShareTarget(0x01010000) == ArithToUint256(arith_uint256{1024}));
    arith_uint256 native;
    native.SetCompact(0x1d00ffff);
    native <<= ho::SHARE_TARGET_SHIFT;
    BOOST_CHECK(ho::ShareTarget(0x1d00ffff) == ArithToUint256(native));
    for (const uint32_t bits : {0U, 0x1d80ffffU, 0x23000001U, 0x02000100U}) {
        BOOST_CHECK_THROW(ho::ShareTarget(bits), std::invalid_argument);
    }
    auto snapshot = Empty();
    snapshot.shares.resize(2);
    snapshot.shares[0].header.nBits = 0x1d00ffff;
    snapshot.shares[0].origin.payout_script = Payout(0x61);
    snapshot.shares[1].header.nBits = 0x1c00ffff;
    snapshot.shares[1].origin.payout_script = Payout(0x62);
    const auto outputs = ho::CalculatePayouts(snapshot, 257);
    BOOST_REQUIRE_EQUAL(outputs.size(), 2);
    BOOST_CHECK_EQUAL(outputs[0].nValue, 1);
    BOOST_CHECK_EQUAL(outputs[1].nValue, 256);
}

BOOST_AUTO_TEST_CASE(owner_attests_job_and_snapshot_but_allows_search)
{
    auto snapshot = Empty();
    auto block = Block(snapshot);
    const auto signed_job = snapshot.job_commitment;
    block.nNonce = 42;
    block.m_nonce2 = 3;
    block.m_nonce3 = 4;
    block.m_extranonce.begin()[0] = 5;
    block.m_time_offset = 6;
    BOOST_CHECK(ho::JobHash(block) == signed_job);
    BOOST_CHECK(Check(block).IsValid());
    block.nTime++;
    Reason(Check(block), "job-commitment");
    block.nTime--;
    // Rehashing changed evidence cannot reuse the old exact-content signature.
    snapshot.post_state.push_back({1, uint256{uint8_t{7}}});
    block.m_mm_rhs = ho::SnapshotHash(snapshot);
    snapshots[block.m_mm_rhs] = std::make_shared<const ho::Snapshot>(snapshot);
    Reason(Check(block), "owner");
}


BOOST_AUTO_TEST_CASE(v5_cross_pool_admissions_parent_cutoff_and_exact_credit_state)
{
    consensus.SharePoolAdmittedLedger = true;
    auto owner_a = Empty(1, 0x61);
    auto owner_b = Empty(1, 0x62);
    owner_b.binding.pool = uint256{uint8_t{4}};
    const auto origin_a = Block(owner_a);
    const auto origin_b = Block(owner_b);
    const auto proof_a = Proof(origin_a, owner_a, 1);
    const auto proof_b = Proof(origin_b, owner_b, 1);
    auto admitted = Empty(1, 0x63);
    admitted.binding.pool = uint256{uint8_t{5}};
    admitted.templates = {Record(origin_a), Record(origin_b)};
    admitted.shares = {proof_a, proof_b};
    SortEvidence(admitted);
    LedgerState(admitted);
    BOOST_REQUIRE_EQUAL(admitted.pending.size(), 2);
    BOOST_CHECK(admitted.settled.empty());
    BOOST_REQUIRE_EQUAL(admitted.certificates.size(), 2);
    BOOST_CHECK(admitted.payouts.front().scriptPubKey == CScript(admitted.binding.payout_script.begin(), admitted.binding.payout_script.end()));
    const auto anchor = Block(admitted);
    const auto checked = Check(anchor);
    BOOST_REQUIRE_MESSAGE(checked.IsValid(), checked.reason);
    Anchor(anchor);
    const auto encoded = ho::EncodeSnapshot(admitted);
    BOOST_CHECK_EQUAL(encoded.front(), ho::LEDGER_VERSION);
    BOOST_CHECK(ho::SnapshotHash(encoded) == ho::SnapshotHash(admitted));
    BOOST_CHECK(ho::EncodeSnapshot(ho::DecodeSnapshot(encoded)) == encoded);
    BOOST_CHECK(ho::RulesHash(ho::LEDGER_VERSION) != ho::RulesHash());

    // The winning job pays only the actual parent's already confirmed A
    // credit. A later proof can be admitted here but is first payable next block.
    const auto late = Proof(origin_a, owner_a, proof_a.header.nNonce + 1);
    auto payment = Empty(2, 0x65);
    payment.templates = {Record(origin_a)};
    payment.shares = {late};
    LedgerState(payment);
    BOOST_REQUIRE_EQUAL(payment.settled.size(), 1);
    BOOST_CHECK(payment.settled.front().proof_id == proof_a.header.GetHash());
    BOOST_REQUIRE_EQUAL(payment.pending.size(), 2);
    BOOST_CHECK(payment.pending.back().proof_id == late.header.GetHash());
    BOOST_REQUIRE_EQUAL(payment.payouts.size(), 1);
    BOOST_CHECK(payment.payouts.front().scriptPubKey == CScript(owner_a.binding.payout_script.begin(), owner_a.binding.payout_script.end()));
    BOOST_CHECK_EQUAL(payment.payouts.front().nValue, REWARD);
    native_checks = 0;
    const auto paid_block = Block(payment);
    const auto paid_result = Check(paid_block);
    BOOST_REQUIRE_MESSAGE(paid_result.IsValid(), paid_result.reason);
    BOOST_CHECK_EQUAL(native_checks, 0); // Parent certified this exact origin.

    auto omission = payment;
    omission.pending.erase(omission.pending.begin());
    Reason(Check(Block(omission)), "ledger-pending");
    auto wrong_script = payment;
    wrong_script.pending.front().payout_script = Payout(0x71);
    Reason(Check(Block(wrong_script)), "ledger-pending");
    auto wrong_work = payment;
    wrong_work.pending.front().native_bits = 0x1d00ffff;
    Reason(Check(Block(wrong_work)), "ledger-pending");
    auto withheld_payment = payment;
    withheld_payment.settled.clear();
    withheld_payment.payouts = ho::CalculatePayouts(withheld_payment, REWARD);
    Reason(Check(Block(withheld_payment)), "ledger-settled");
    auto wrong_payee = payment;
    wrong_payee.settled.front().payout_script = Payout(0x71);
    wrong_payee.payouts = ho::CalculatePayouts(wrong_payee, REWARD);
    Reason(Check(Block(wrong_payee)), "ledger-settled");
    auto no_cert = payment;
    no_cert.certificates.clear();
    Reason(Check(Block(no_cert)), "ledger-certificates");
    auto duplicate = payment;
    duplicate.shares = {proof_a};
    duplicate.post_state = admitted.post_state;
    Reason(Check(Block(duplicate)), "repeat-payment");
    auto wrong_amount = payment;
    --wrong_amount.payouts.front().nValue;
    Reason(Check(Block(wrong_amount)), "reward");

    // Confirmation is branch-local. A competing C block retains both pools'
    // credits; A's next block then pays exactly A, with B still pending.
    auto competing = Empty(2, 0x63);
    competing.binding.pool = admitted.binding.pool;
    LedgerState(competing);
    BOOST_CHECK(competing.pending == admitted.pending);
    BOOST_CHECK(competing.settled.empty());
    const auto competing_block = Block(competing);
    BOOST_REQUIRE(Check(competing_block).IsValid());
    Anchor(competing_block);
    auto after_c = Empty(3);
    LedgerState(after_c);
    BOOST_REQUIRE_EQUAL(after_c.settled.size(), 1);
    BOOST_CHECK(after_c.settled.front().proof_id == proof_a.header.GetHash());
    BOOST_REQUIRE(Check(Block(after_c)).IsValid());
    Anchor(paid_block);
    auto after_a = Empty(3);
    LedgerState(after_a);
    BOOST_REQUIRE_EQUAL(after_a.settled.size(), 1);
    BOOST_CHECK(after_a.settled.front().proof_id == late.header.GetHash());
    BOOST_REQUIRE(Check(Block(after_a)).IsValid());
}

BOOST_AUTO_TEST_CASE(v5_confirmed_work_outlives_fresh_proof_and_certificate_age)
{
    consensus.SharePoolAdmittedLedger = true;
    auto opening = Empty();
    const auto origin = Block(opening);
    const auto proof = Proof(origin, opening, 1);
    auto admission = Empty(1, 0x62);
    admission.binding.pool = uint256{uint8_t{4}};
    admission.templates = {Record(origin)};
    admission.shares = {proof};
    LedgerState(admission);
    auto block = Block(admission);
    BOOST_REQUIRE(Check(block).IsValid());
    Anchor(block);
    for (uint32_t height{2}; height <= 5; ++height) {
        auto carry = Empty(height, 0x62);
        carry.binding.pool = admission.binding.pool;
        LedgerState(carry);
        BOOST_CHECK(carry.pending == admission.pending);
        BOOST_CHECK(carry.settled.empty());
        BOOST_CHECK_EQUAL(carry.certificates.empty(), height == 5);
        BOOST_CHECK_EQUAL(carry.post_state.empty(), height == 5);
        block = Block(carry);
        const auto result = Check(block);
        BOOST_REQUIRE_MESSAGE(result.IsValid(), result.reason);
        Anchor(block);
    }
    const auto late = Proof(origin, opening, proof.header.nNonce + 1);
    Reason(ho::CheckShareProof(late, origin, &indexes[5], indexes[5].nTime + 1,
                               consensus, Lookup(), Native()), "share-context");
    auto pay = Empty(6);
    LedgerState(pay);
    BOOST_CHECK(pay.pending.empty());
    BOOST_REQUIRE_EQUAL(pay.settled.size(), 1);
    BOOST_CHECK(pay.settled.front().proof_id == proof.header.GetHash());
    BOOST_CHECK(pay.post_state.empty());
    BOOST_CHECK(pay.certificates.empty());
    BOOST_REQUIRE(Check(Block(pay)).IsValid());
}

BOOST_AUTO_TEST_CASE(v5_certificates_bind_witness_body_owner_and_actual_parent)
{
    consensus.SharePoolAdmittedLedger = true;
    auto opening = Empty();
    auto origin = Block(opening);
    auto admission = Empty(1, 0x62);
    admission.binding.pool = uint256{uint8_t{4}};
    admission.templates = {Record(origin)};
    admission.shares = {Proof(origin, opening, 1)};
    LedgerState(admission);
    const auto anchor = Block(admission);
    BOOST_REQUIRE(Check(anchor).IsValid());
    Anchor(anchor);
    const auto refuse_native = [](const CBlock&, const CBlockIndex*) { return ho::Result::Invalid("fixture-native-refusal"); };
    const auto fresh = Proof(origin, opening, admission.shares.front().header.nNonce + 1);
    BOOST_CHECK(ho::CheckShareProof(fresh, origin, &indexes[1], anchor.nTime + 1,
                                   consensus, Lookup(), refuse_native).IsValid());
    BOOST_CHECK(ho::CheckHistoricalTemplate(origin, &indexes[1], anchor.nTime + 1,
                                            consensus, Lookup(), refuse_native).IsValid());
    // A different native parent snapshot has no certificate for this origin.
    auto competing = Empty(1, 0x63);
    LedgerState(competing);
    const auto competing_block = Block(competing);
    Anchor(competing_block);
    Reason(ho::CheckShareProof(fresh, origin, &indexes[1], anchor.nTime + 1,
                               consensus, Lookup(), refuse_native), "origin-body: fixture-native-refusal");
    Anchor(anchor);

    auto witness_changed = origin;
    CMutableTransaction coinbase{*origin.vtx.front()};
    coinbase.vin.front().scriptWitness.stack = {{0x01}};
    witness_changed.vtx.front() = MakeTransactionRef(std::move(coinbase));
    BOOST_CHECK(witness_changed.hashMerkleRoot == BlockMerkleRoot(witness_changed));
    BOOST_CHECK(ho::TemplateId(witness_changed) == ho::TemplateId(origin));
    BOOST_CHECK(ho::OriginCertificateId(witness_changed) != ho::OriginCertificateId(origin));
    Reason(ho::CheckHistoricalTemplate(witness_changed, &indexes[1], anchor.nTime + 1,
                                        consensus, Lookup(), refuse_native), "job-commitment");
    // Even a newly valid owner signature for changed witness bytes cannot
    // reuse the prior certificate: native verification is required again.
    Reseal(witness_changed);
    Reason(ho::CheckHistoricalTemplate(witness_changed, &indexes[1], anchor.nTime + 1,
                                        consensus, Lookup(), refuse_native), "origin-body: fixture-native-refusal");
    auto changed_opening = *snapshots.at(witness_changed.m_mm_rhs);
    auto fabricated = Empty(2, 0x64);
    fabricated.templates = {Record(witness_changed)};
    fabricated.shares = {Proof(witness_changed, changed_opening, 1)};
    LedgerState(fabricated); // Proposed current cert exists, but is not trusted.
    const auto fabricated_block = Block(fabricated);
    Reason(ho::CheckSnapshot(fabricated_block, &indexes[1], consensus, Lookup(), refuse_native, REWARD),
           "origin-body: fixture-native-refusal");
    const auto original_lookup = Lookup();
    const auto unavailable_opening = [&](const uint256& hash) -> std::shared_ptr<const ho::Snapshot> {
        return hash == origin.m_mm_rhs ? nullptr : original_lookup(hash);
    };
    BOOST_CHECK(ho::CheckHistoricalTemplate(origin, &indexes[1], anchor.nTime + 1,
                                            consensus, unavailable_opening, refuse_native).IsMissing());
}

BOOST_AUTO_TEST_CASE(v5_byte_bounded_oldest_prefix_preserves_all_confirmed_credits)
{
    consensus.SharePoolAdmittedLedger = true;
    auto parent = Empty();
    // Synthetic metadata fixture for exact byte selection, not a PoW fixture.
    for (uint32_t i{1}; i <= 12000; ++i) {
        parent.pending.push_back({1, 1, ArithToUint256(arith_uint256{i}), parent.binding.pool,
                                  SHARE_BITS, Payout(0x61)});
    }
    auto next = Empty(2);
    ho::ApplyLedgerState(next, &parent);
    BOOST_REQUIRE(!next.settled.empty());
    BOOST_CHECK(GetSerializeSize(next.settled) <= ho::MAX_SETTLED_BYTES);
    auto one_more = next.settled;
    one_more.push_back(next.pending.front());
    BOOST_CHECK(GetSerializeSize(one_more) > ho::MAX_SETTLED_BYTES);
    std::vector<ho::LedgerCredit> reunited = next.settled;
    reunited.insert(reunited.end(), next.pending.begin(), next.pending.end());
    BOOST_CHECK(reunited == parent.pending);
    BOOST_CHECK(next.settled.front().proof_id == parent.pending.front().proof_id);

    // Fresh admissions cannot evict a confirmed credit when pending is full.
    parent.pending.clear();
    const size_t maximum = (ho::MAX_PENDING_BYTES - 3) / 99;
    for (uint32_t i{1}; i <= maximum; ++i) {
        parent.pending.push_back({1, 1, ArithToUint256(arith_uint256{i}), uint256{uint8_t{4}}, SHARE_BITS, Payout(0x61)});
    }
    auto opening = Empty();
    const auto origin = Block(opening);
    next = Empty(2);
    next.templates = {Record(origin)};
    next.shares = {Proof(origin, opening, 1)};
    BOOST_CHECK_THROW(ho::ApplyLedgerState(next, &parent), std::ios_base::failure);
    BOOST_CHECK(next.pending.empty()); // Exception leaves derived arrays intact.
    BOOST_CHECK_EQUAL(parent.pending.size(), maximum);

    auto weighted = Empty();
    weighted.settled = {
        {1, 1, uint256{uint8_t{1}}, weighted.binding.pool, 0x1d00ffff, Payout(0x61)},
        {1, 1, uint256{uint8_t{2}}, weighted.binding.pool, 0x1c00ffff, Payout(0x62)},
    };
    const auto outputs = ho::CalculatePayouts(weighted, 257);
    BOOST_REQUIRE_EQUAL(outputs.size(), 2);
    BOOST_CHECK_EQUAL(outputs[0].nValue, 1);
    BOOST_CHECK_EQUAL(outputs[1].nValue, 256);
}

BOOST_AUTO_TEST_CASE(v5_parent_certificate_renews_worked_graph_depth_budget)
{
    consensus.SharePoolAdmittedLedger = true;
    auto opening = Empty();
    LedgerState(opening);
    auto origin = Block(opening);
    // Every link records actual proved work in its own proposed admission
    // state. No proposed state is trusted until a native block anchors it.
    for (uint32_t i{0}; i < ho::MAX_DEPENDENCY_DEPTH - 1; ++i) {
        auto next = Empty();
        next.templates = {Record(origin)};
        next.shares = {Proof(origin, opening, 1)};
        LedgerState(next);
        origin = Block(next);
        opening = std::move(next);
    }
    BOOST_REQUIRE(ho::CheckMiningJob(origin, &indexes[0], consensus, Lookup(), Native(), REWARD).IsValid());
    auto admission = Empty(1, 0x62);
    admission.binding.pool = uint256{uint8_t{4}};
    admission.templates = {Record(origin)};
    admission.shares = {Proof(origin, opening, 1)};
    LedgerState(admission);
    const auto anchor = Block(admission);
    BOOST_REQUIRE(Check(anchor).IsValid());
    Reason(ho::CheckMiningJob(anchor, &indexes[0], consensus, Lookup(), Native(), REWARD), "dependency-depth");
    Anchor(anchor);
    // A fresh proof of that deeply worked origin can now use the exact
    // certificate in the actual native parent instead of its old 63-edge DAG.
    const auto fresh = Proof(origin, opening, admission.shares.front().header.nNonce + 1);
    native_checks = 0;
    BOOST_REQUIRE(ho::CheckShareProof(fresh, origin, &indexes[1], anchor.nTime + 1,
                                     consensus, Lookup(), Native()).IsValid());
    BOOST_CHECK_EQUAL(native_checks, 0);
    auto next = Empty(2);
    next.templates = {Record(origin)};
    next.shares = {fresh};
    LedgerState(next);
    const auto next_block = Block(next);
    BOOST_REQUIRE(ho::CheckMiningJob(next_block, &indexes[1], consensus, Lookup(), Native(), REWARD).IsValid());
    BOOST_CHECK_EQUAL(native_checks, 0);
    auto next_opening = next;
    auto next_origin = next_block;
    // Continue real worked jobs past the original total depth limit. Each
    // validation walk still has its bounded depth from the current parent.
    for (uint32_t i{0}; i < 3; ++i) {
        auto refresh = Empty(2);
        refresh.templates = {Record(next_origin)};
        refresh.shares = {Proof(next_origin, next_opening, 1)};
        LedgerState(refresh);
        next_origin = Block(refresh);
        next_opening = std::move(refresh);
        const auto result = ho::CheckMiningJob(next_origin, &indexes[1], consensus, Lookup(), Native(), REWARD);
        BOOST_REQUIRE_MESSAGE(result.IsValid(), result.reason);
    }
}

BOOST_AUTO_TEST_CASE(v7_compact_jobs_reconstruct_exact_shares_and_ignore_derived_caches)
{
    consensus.SharePoolTides = true;
    consensus.SharePoolCompactTides = true;
    auto initial = CompactEmpty();
    const auto origin = CompactBlock(initial);
    auto snapshot = CompactEmpty(1, 0x62);
    snapshot.templates = {Record(origin)};
    for (uint32_t i{0}; i < 100; ++i) {
        auto share = Proof(origin, initial, i * 256);
        share.header.m_nonce2 = i + 1;
        share.header.m_nonce3 = i + 2;
        share.header.m_extranonce.begin()[i % 16] = static_cast<uint8_t>(i + 1);
        share.header.m_time_offset = i + 3;
        snapshot.shares.push_back(share);
    }
    SortEvidence(snapshot);
    CompactState(snapshot);
    const auto block = CompactBlock(snapshot);
    const auto bytes = ho::EncodeSnapshot(snapshot);
    const auto decoded = ho::DecodeSnapshot(bytes);
    BOOST_CHECK(decoded.post_state.empty());
    BOOST_CHECK(decoded.certificates.empty());
    BOOST_REQUIRE_EQUAL(decoded.shares.size(), snapshot.shares.size());
    for (size_t i{0}; i < snapshot.shares.size(); ++i) {
        DataStream old_share, new_share;
        old_share << snapshot.shares[i];
        new_share << decoded.shares[i];
        BOOST_CHECK(old_share.size() == new_share.size() && std::equal(old_share.begin(), old_share.end(), new_share.begin()));
    }
    const auto usage = ho::MeasureSnapshotResources(snapshot);
    BOOST_CHECK_EQUAL(usage.encoded_bytes, bytes.size());
    BOOST_CHECK_EQUAL(ComponentBytes(usage), bytes.size());
    BOOST_CHECK_EQUAL(usage.jobs, 1);
    BOOST_CHECK_EQUAL(usage.job_table_bytes, 1 + 1 + GetSerializeSize(initial.binding) + GetSerializeSize(initial.authorization));
    BOOST_CHECK_EQUAL(usage.share_bytes, 1 + 100 * 33);
    BOOST_CHECK_EQUAL(usage.state_bytes, 0);
    BOOST_CHECK_EQUAL(usage.certificate_bytes, 0);
    BOOST_CHECK_EQUAL(usage.history_bytes, 32);
    BOOST_CHECK(Check(block).IsValid());
    const auto contents = ho::SnapshotContentsHash(snapshot);
    snapshot.post_state = {{0, uint256{}}, {0, uint256{}}};
    snapshot.certificates = {{0, {}, {}, {}}, {0, {}, {}, {}}};
    BOOST_CHECK(ho::EncodeSnapshot(snapshot) == bytes);
    BOOST_CHECK(ho::SnapshotContentsHash(snapshot) == contents);
    snapshots[block.m_mm_rhs] = std::make_shared<const ho::Snapshot>(snapshot);
    BOOST_CHECK(Check(block).IsValid());
    BOOST_CHECK(ho::ProfileSnapshotHash(bytes, ho::COMPACT_TIDES_VERSION) == block.m_mm_rhs);
    BOOST_CHECK(ho::ProfileSnapshotHash(bytes, ho::TIDES_VERSION) != block.m_mm_rhs);
    BOOST_CHECK(ho::RulesHash(ho::COMPACT_TIDES_VERSION) != ho::RulesHash(ho::TIDES_VERSION));
    BOOST_CHECK(ho::ShareTarget(0x1d00ffff, ho::COMPACT_TIDES_VERSION) == ho::ShareTarget(0x1d00ffff, ho::TIDES_VERSION));
}

BOOST_AUTO_TEST_CASE(v7_compact_dictionary_rejects_conflicts_unused_entries_and_search_rebinding)
{
    consensus.SharePoolTides = true;
    consensus.SharePoolCompactTides = true;
    auto initial = CompactEmpty();
    const auto origin = CompactBlock(initial);
    auto snapshot = CompactEmpty(1, 0x62);
    snapshot.templates = {Record(origin)};
    snapshot.shares = {Proof(origin, initial, 1), Proof(origin, initial, 512)};
    SortEvidence(snapshot);
    CompactState(snapshot);
    const auto good = snapshot;
    const auto encoded = ho::EncodeSnapshot(good);
    const auto usage = ho::MeasureSnapshotResources(good);
    const size_t dictionary = usage.binding_bytes + usage.transaction_table_bytes + usage.template_table_bytes;
    auto corrupt = encoded;
    corrupt.at(dictionary + 1) = 1; // Only template index0 exists.
    BOOST_CHECK_THROW(ho::DecodeSnapshot(corrupt), std::ios_base::failure);
    corrupt = encoded;
    const size_t proofs = dictionary + usage.job_table_bytes;
    corrupt.at(proofs + 1) = 1; // Only dictionary index0 exists.
    BOOST_CHECK_THROW(ho::DecodeSnapshot(corrupt), std::ios_base::failure);
    corrupt = encoded;
    corrupt.at(proofs) = 0;
    corrupt.erase(corrupt.begin() + proofs + 1, corrupt.begin() + proofs + usage.share_bytes);
    BOOST_CHECK_THROW(ho::DecodeSnapshot(corrupt), std::ios_base::failure); // Unused descriptor.
    snapshot.shares.back().authorization[0] ^= 1;
    BOOST_CHECK_THROW(ho::EncodeSnapshot(snapshot), std::ios_base::failure);
    snapshot = good;
    snapshot.shares.back().origin.payout_script = Payout(0x63);
    BOOST_CHECK_THROW(ho::EncodeSnapshot(snapshot), std::ios_base::failure);
    snapshot = good;
    snapshot.shares.back().header.nTime++;
    BOOST_CHECK_THROW(ho::EncodeSnapshot(snapshot), std::ios_base::failure);
    snapshot = good;
    for (auto& share : snapshot.shares) share.authorization[0] ^= 1;
    const auto wrong_auth = CompactBlock(snapshot);
    Reason(Check(wrong_auth), "share-authorization");
    snapshot = good;
    snapshot.shares.resize(ho::MAX_COMPACT_SHARES + 1, snapshot.shares.front());
    BOOST_CHECK_THROW(ho::EncodeSnapshot(snapshot), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(v7_bounded_native_suffix_reconstructs_expiry_and_repeat_state_after_nine_heights)
{
    consensus.SharePoolTides = true;
    consensus.SharePoolCompactTides = true;
    std::vector<CBlock> origins;
    std::vector<Share> admitted;
    for (uint32_t height{1}; height <= 9; ++height) {
        auto job = CompactEmpty(height);
        origins.push_back(CompactBlock(job));
        auto settlement = CompactEmpty(height, 0x62);
        settlement.templates = {Record(origins.back())};
        settlement.shares = {Proof(origins.back(), job, 1)};
        admitted.push_back(settlement.shares.front());
        CompactState(settlement);
        BOOST_CHECK_EQUAL(settlement.post_state.size(), std::min<size_t>(height, MAX_SHARE_AGE + 1));
        BOOST_CHECK_EQUAL(settlement.certificates.size(), std::min<size_t>(height, MAX_SHARE_AGE + 1));
        const auto block = CompactBlock(settlement);
        const auto checked = Check(block);
        BOOST_REQUIRE_MESSAGE(checked.IsValid(), checked.reason);
        Anchor(block);
    }
    auto next = CompactEmpty(10);
    std::vector<uint256> reads;
    const ho::Lookup recorded = [&](const uint256& hash) {
        reads.push_back(hash);
        return Lookup()(hash);
    };
    next.post_state = {{0, uint256{}}};
    next.certificates = {{0, {}, {}, {}}};
    BOOST_REQUIRE(ho::MaterializeTidesState(next, &indexes[9], consensus, recorded).IsValid());
    BOOST_REQUIRE_EQUAL(reads.size(), 3);
    for (size_t i{0}; i < reads.size(); ++i) BOOST_CHECK(reads[i] == indexes[7 + i].m_mm_rhs);
    BOOST_CHECK_EQUAL(next.post_state.size(), 3);
    BOOST_CHECK_EQUAL(next.certificates.size(), 3);
    for (const auto& state : next.post_state) BOOST_CHECK_GE(state.origin_height, 7);
    const auto retained = snapshots.at(indexes[8].m_mm_rhs);
    snapshots.erase(indexes[8].m_mm_rhs);
    const auto missing = ho::MaterializeTidesState(next, &indexes[9], consensus, Lookup());
    BOOST_CHECK(missing.IsMissing());
    BOOST_REQUIRE_EQUAL(missing.missing.size(), 1);
    BOOST_CHECK(missing.missing.front() == indexes[8].m_mm_rhs);
    snapshots[indexes[8].m_mm_rhs] = retained;
    const auto fourth = snapshots.at(indexes[4].m_mm_rhs);
    const auto fifth = snapshots.at(indexes[5].m_mm_rhs);
    snapshots.erase(indexes[4].m_mm_rhs);
    snapshots.erase(indexes[5].m_mm_rhs);
    const auto opening = snapshots.at(origins[6].m_mm_rhs);
    const auto fresh = Proof(origins[6], *opening, 512);
    native_checks = 0;
    // Actual parent9's certificate derivation opens native6..8. Origin7's
    // redundant old4..6 suffix must not be required by the exact shortcut.
    const auto certified = ho::CheckShareProof(fresh, origins[6], &indexes[9], indexes[9].nTime + 1,
                                              consensus, Lookup(), Native());
    BOOST_REQUIRE_MESSAGE(certified.IsValid(), certified.reason);
    BOOST_CHECK_EQUAL(native_checks, 0);
    BOOST_CHECK(ho::CheckHistoricalTemplate(origins[6], &indexes[9], indexes[9].nTime + 1,
                                           consensus, Lookup(), Native()).IsValid());
    auto changed = origins[6];
    ++changed.nTime;
    auto changed_opening = *opening;
    changed_opening.job_commitment = ho::JobHash(changed);
    changed_opening.authorization = Sign(changed_opening);
    changed.m_mm_rhs = ho::SnapshotHash(changed_opening);
    snapshots[changed.m_mm_rhs] = std::make_shared<const ho::Snapshot>(changed_opening);
    // A newly signed exact job without the certificate still needs its own
    // old ancestry. It cannot inherit the shortcut by height, owner or pool.
    const auto uncertified = ho::CheckHistoricalTemplate(changed, &indexes[9], indexes[9].nTime + 1,
                                                        consensus, Lookup(), Native());
    BOOST_CHECK(uncertified.IsMissing());
    snapshots[indexes[4].m_mm_rhs] = fourth;
    snapshots[indexes[5].m_mm_rhs] = fifth;
    next.templates = {Record(origins[6])};
    next.shares = {admitted[6]}; // Origin7 is still eligible at height10 but already paid.
    BOOST_CHECK(ho::MaterializeTidesState(next, &indexes[9], consensus, Lookup()).status == ho::Status::Invalid);
    next = CompactEmpty(10);
    next.templates = {Record(origins[5])};
    next.shares = {admitted[5]}; // Origin6 has expired and cannot be reintroduced.
    BOOST_CHECK(ho::MaterializeTidesState(next, &indexes[9], consensus, Lookup()).status == ho::Status::Invalid);
    next = CompactEmpty(10);
    next.history_head = uint256{uint8_t{0x99}};
    const auto wrong_history = CompactBlock(next);
    Reason(Check(wrong_history), "tides-history");
    next = CompactEmpty(10);
    next.binding.native_parent = uint256{uint8_t{0xee}};
    BOOST_CHECK(ho::MaterializeTidesState(next, &indexes[9], consensus, Lookup()).status == ho::Status::Invalid);
}

BOOST_AUTO_TEST_CASE(v7_preparation_and_full_validation_reauthenticate_ancestry_evidence)
{
    consensus.SharePoolTides = true;
    consensus.SharePoolCompactTides = true;
    auto initial = CompactEmpty();
    const auto origin = CompactBlock(initial);
    auto first = CompactEmpty();
    first.templates = {Record(origin)};
    first.shares = {Proof(origin, initial, 1)};
    CompactState(first);
    const auto settled = CompactBlock(first);
    BOOST_REQUIRE(Check(settled).IsValid());
    Anchor(settled);
    auto child = CompactEmpty(2);
    const auto child_block = CompactBlock(child);
    const auto parent_hash = indexes[1].m_mm_rhs;
    const auto parent = snapshots.at(parent_hash);
    const auto materialize = [&] { return ho::MaterializeTidesState(child, &indexes[1], consensus, Lookup()); };
    std::vector<CTxOut> payouts;
    const auto account = [&] { return ho::CalculateTidesPayouts(child, &indexes[1], indexes[1].nBits,
                                                              consensus, Lookup(), REWARD, payouts); };
    BOOST_REQUIRE(materialize().IsValid());
    BOOST_REQUIRE(account().IsValid());
    const auto expected = payouts;
    // A previously seen address cannot authenticate changed canonical bytes.
    auto corrupt = *parent;
    corrupt.authorization[0] ^= 1;
    snapshots[parent_hash] = std::make_shared<const ho::Snapshot>(corrupt);
    BOOST_CHECK(materialize().IsMissing());
    BOOST_CHECK(Check(child_block).IsMissing());
    // Correctly rehashing the corrupted signature still cannot authenticate it.
    const auto bad_hash = ho::SnapshotHash(corrupt);
    snapshots[bad_hash] = std::make_shared<const ho::Snapshot>(corrupt);
    indexes[1].m_mm_rhs = bad_hash;
    Reason(materialize(), "compact-state-parent");
    BOOST_CHECK(account().status == ho::Status::Invalid);
    // A warm payout cursor owns an already authenticated admission summary;
    // full validation must nevertheless reopen its required recent ancestry.
    // Restoring that evidence recovers both reconstruction and accounting.
    indexes[1].m_mm_rhs = parent_hash;
    snapshots[parent_hash] = parent;
    BOOST_REQUIRE(materialize().IsValid());
    BOOST_REQUIRE(account().IsValid());
    BOOST_CHECK(payouts == expected);
    snapshots.erase(parent_hash);
    BOOST_CHECK(materialize().IsMissing());
    BOOST_CHECK(Check(child_block).IsMissing());
    snapshots[parent_hash] = parent;
    BOOST_REQUIRE(materialize().IsValid());
    BOOST_REQUIRE(account().IsValid());
    BOOST_CHECK(payouts == expected);
}

BOOST_AUTO_TEST_CASE(v7_shared_optional_retention_preserves_exact_validation_results)
{
    consensus.SharePoolTides = true;
    consensus.SharePoolCompactTides = true;
    auto initial = CompactEmpty();
    const auto origin = CompactBlock(initial);
    auto first = CompactEmpty();
    first.templates = {Record(origin)};
    first.shares = {Proof(origin, initial, 1)};
    CompactState(first);
    const auto settled = CompactBlock(first);
    BOOST_REQUIRE(Check(settled).IsValid());
    Anchor(settled);
    auto child = CompactEmpty(2);
    const auto block = CompactBlock(child);
    auto proof = Proof(origin, initial, first.shares.front().header.nNonce + 1);
    auto bad_proof = proof;
    bad_proof.authorization[0] ^= 1;
    auto wrong_payout = block;
    CMutableTransaction coinbase{*wrong_payout.vtx.front()};
    --coinbase.vout.front().nValue;
    wrong_payout.vtx.front() = MakeTransactionRef(std::move(coinbase));
    wrong_payout.hashMerkleRoot = BlockMerkleRoot(wrong_payout);
    Reseal(wrong_payout);
    auto bad_owner = block;
    auto unauthorized = *snapshots.at(block.m_mm_rhs);
    unauthorized.authorization[0] ^= 1;
    bad_owner.m_mm_rhs = ho::SnapshotHash(unauthorized);
    snapshots[bad_owner.m_mm_rhs] = std::make_shared<const ho::Snapshot>(unauthorized);

    const auto validate = [&](size_t maximum, const auto& evaluate,
                              std::optional<uint256> missing = {}, bool malformed = false) {
        auto budget = std::make_shared<DecodedSnapshotRetentionBudget>(maximum);
        ho::Result result;
        {
            DecodedSnapshotCache cache{ho::MAX_DEPENDENCY_BYTES, 1024, budget};
            const ho::Lookup lookup = [&](const uint256& hash) -> std::shared_ptr<const ho::Snapshot> {
                if (malformed) throw ho::MalformedSnapshot("authenticated malformed bytes");
                if (missing && hash == *missing) return {};
                if (auto retained = cache.Get(hash)) return retained;
                const auto found = snapshots.find(hash);
                if (found == snapshots.end()) return {};
                const auto raw = ho::EncodeSnapshot(*found->second);
                auto decoded = std::make_shared<const ho::Snapshot>(ho::DecodeSnapshot(raw));
                cache.Put(hash, decoded, raw.size());
                // Same availability rule as the native store lookup: denied
                // optional retention never hides this freshly decoded value.
                return decoded;
            };
            result = evaluate(lookup);
            BOOST_CHECK_LE(budget->Bytes(), maximum);
            if (maximum <= 1) BOOST_CHECK_EQUAL(cache.Bytes(), 0);
        }
        BOOST_CHECK_EQUAL(budget->Bytes(), 0);
        return result;
    };
    std::vector<ho::Result> expected;
    const auto& origin_snapshot = *snapshots.at(origin.m_mm_rhs);
    const size_t one_record = DecodedSnapshotCacheCharge(origin_snapshot, ho::EncodeSnapshot(origin_snapshot).size());
    for (const size_t maximum : {DEFAULT_DECODED_SNAPSHOT_RETENTION_BYTES, one_record, size_t{1}, size_t{0}}) {
        const auto check = [&](const CBlock& value, std::optional<uint256> missing = {}, bool malformed = false) {
            return validate(maximum, [&](const ho::Lookup& lookup) {
                return ho::CheckSnapshot(value, &indexes[1], consensus, lookup, Native(), REWARD);
            }, missing, malformed);
        };
        std::vector<ho::Result> results;
        results.push_back(check(block));
        results.push_back(validate(maximum, [&](const ho::Lookup& lookup) {
            return ho::CheckHistoricalTemplate(origin, &indexes[1], indexes[1].nTime + 1, consensus, lookup, Native());
        }));
        const auto check_proof = [&](const Share& value) {
            return validate(maximum, [&](const ho::Lookup& lookup) {
                return ho::CheckShareProof(value, origin, &indexes[1], indexes[1].nTime + 1, consensus, lookup, Native());
            });
        };
        results.push_back(check_proof(proof));
        results.push_back(validate(maximum, [&](const ho::Lookup& lookup) {
            return ho::CheckMiningJob(block, &indexes[1], consensus, lookup, Native(), REWARD);
        }));
        results.push_back(check(wrong_payout));
        results.push_back(check(bad_owner));
        results.push_back(check_proof(bad_proof));
        results.push_back(check(block, {}, true));
        results.push_back(check(block, indexes[1].m_mm_rhs));
        for (size_t i{0}; i < 4; ++i) BOOST_REQUIRE_MESSAGE(results[i].IsValid(), results[i].reason);
        for (size_t i{4}; i < 8; ++i) BOOST_CHECK(results[i].status == ho::Status::Invalid);
        BOOST_REQUIRE(results[8].IsMissing());
        BOOST_CHECK(!results[8].missing.empty());
        if (expected.empty()) expected = results;
        else for (size_t i{0}; i < results.size(); ++i) {
            BOOST_CHECK(results[i].status == expected[i].status);
            BOOST_CHECK_EQUAL(results[i].reason, expected[i].reason);
            BOOST_CHECK(results[i].missing == expected[i].missing);
            BOOST_CHECK(results[i].expected_reward == expected[i].expected_reward);
        }
    }
}

BOOST_AUTO_TEST_CASE(v7_compact_dictionary_and_proof_indexes_cross_compactsize_boundaries)
{
    consensus.SharePoolTides = true;
    consensus.SharePoolCompactTides = true;
    auto initial = CompactEmpty();
    const auto base = CompactBlock(initial);
    auto snapshot = CompactEmpty(1, 0x62);
    // Encoding-only geometry: separate RHS commitments give exact distinct
    // template IDs. This fixture makes no origin-validity claim for those RHSs.
    for (uint32_t i{0}; i < 254; ++i) {
        CBlock origin{base};
        origin.m_mm_rhs = ArithToUint256(arith_uint256{i + 1});
        snapshot.templates.push_back(Record(origin));
        Share share{origin.GetBlockHeader(), initial.binding, initial.authorization};
        share.header.nNonce = i + 1;
        snapshot.shares.push_back(share);
    }
    SortEvidence(snapshot);
    const auto bytes = ho::EncodeSnapshot(snapshot);
    const auto decoded = ho::DecodeSnapshot(bytes);
    BOOST_CHECK(ho::EncodeSnapshot(decoded) == bytes);
    const auto usage = ho::MeasureSnapshotResources(snapshot);
    BOOST_CHECK_EQUAL(usage.jobs, 254);
    BOOST_CHECK_EQUAL(usage.job_table_bytes, 3 + 253 * (1 + 348) + (3 + 348));
    BOOST_CHECK_EQUAL(usage.share_bytes, 3 + 253 * 33 + 35);
    BOOST_CHECK_EQUAL(ComponentBytes(usage), bytes.size());
    const size_t dictionary = usage.binding_bytes + usage.transaction_table_bytes + usage.template_table_bytes;
    auto noncanonical = bytes;
    // First descriptor's template index0 must use the single-byte form.
    noncanonical[dictionary + 3] = 0xfd;
    noncanonical.insert(noncanonical.begin() + dictionary + 4, {0, 0});
    BOOST_CHECK_THROW(ho::DecodeSnapshot(noncanonical), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(v7_compact_graph_keeps_full_share_validation_work_bound)
{
    consensus.SharePoolTides = true;
    consensus.SharePoolCompactTides = true;
    auto initial = CompactEmpty();
    const auto base = CompactBlock(initial);
    auto snapshot = CompactEmpty(1, 0x62);
    snapshot.templates = {Record(base)};
    snapshot.shares.reserve(ho::MAX_COMPACT_SHARES);
    for (uint32_t i{0}; i < ho::MAX_COMPACT_SHARES; ++i) {
        Share share{base.GetBlockHeader(), initial.binding, initial.authorization};
        share.header.nNonce = i + 1;
        snapshot.shares.push_back(share);
    }
    SortEvidence(snapshot);
    CompactState(snapshot);
    auto origin = CompactBlock(snapshot);
    CBlock boundary;
    for (uint32_t level{2}; level <= 5; ++level) {
        snapshot.templates = {Record(base), Record(origin)};
        SortEvidence(snapshot);
        // These are alternative jobs at the same native height; their complete
        // current deltas overlap, while no actual native parent admitted them.
        origin = CompactBlock(snapshot);
        if (level == 4) boundary = origin;
    }
    // Five distinct compact snapshots fit well below64MiB on the wire but
    // exceed131072 reconstructed proofs. A sixth zero-proof opening is shared.
    Reason(Check(origin), "dependency-shares");
    native_checks = 0;
    const auto accepted = Check(boundary);
    BOOST_REQUIRE_MESSAGE(accepted.IsValid(), accepted.reason);
    BOOST_CHECK_EQUAL(native_checks, 4);
}

BOOST_AUTO_TEST_CASE(v8_assignment_wire_rules_and_exact_target_vectors)
{
    using boost::multiprecision::cpp_int;
    BOOST_CHECK_EQUAL(ho::RulesHash(ho::VARIABLE_TIDES_VERSION).GetHex(), "173ff6fa511f227cc8d4751bb15373afdca5c8ec235dc69ca2680d7ade13ea31");
    const cpp_int space = cpp_int{1} << 256;
    Share share;
    share.origin.version = ho::VARIABLE_TIDES_VERSION;
    for (unsigned bits{0}; bits <= 255; ++bits) {
        share.origin.share_work_bits = bits;
        for (const uint32_t native : {0x207fffffU, 0x1d00ffffU, 0x1c0fffffU}) {
            share.header.nBits = native;
            const cpp_int work{"0x" + ho::TidesShareWork(share).GetHex()};
            const cpp_int target{"0x" + ho::ShareTarget(share).GetHex()};
            BOOST_CHECK(work == cpp_int{1} << bits);
            BOOST_CHECK((target + 1) * work == space);
        }
    }
    share.header.nBits = 0;
    BOOST_CHECK_THROW(ho::ShareTarget(share), std::invalid_argument);
    BOOST_CHECK_THROW(ho::TidesShareWork(share), std::invalid_argument);
    BOOST_CHECK_THROW(ho::ShareTarget(SHARE_BITS, ho::VARIABLE_TIDES_VERSION), std::invalid_argument);

    auto binding = Owner();
    binding.version = ho::VARIABLE_TIDES_VERSION;
    binding.rules = ho::RulesHash(binding.version);
    binding.share_work_bits = 37;
    DataStream encoded;
    encoded << binding;
    const size_t position = 1 + 32 + 32 + 4 + 32 + 32 + 32 + GetSerializeSize(binding.payout_script);
    BOOST_CHECK_EQUAL(UCharCast(encoded.data())[position], 37);
    Envelope decoded;
    encoded >> decoded;
    BOOST_CHECK_EQUAL(decoded.share_work_bits, 37);
    binding.version = ho::COMPACT_TIDES_VERSION;
    BOOST_CHECK_THROW(GetSerializeSize(binding), std::ios_base::failure);
    binding.share_work_bits = 0;
    DataStream legacy;
    legacy << binding;
    legacy >> decoded; // Reusing a decoder object cannot inherit an old assignment.
    BOOST_CHECK_EQUAL(decoded.share_work_bits, 0);
    share.origin = binding;
    share.origin.share_work_bits = 1;
    share.header.nBits = SHARE_BITS;
    BOOST_CHECK_THROW(ho::TidesShareWork(share), std::invalid_argument);
    BOOST_CHECK_THROW(ho::ShareTarget(share), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(v8_assigned_target_is_attested_and_native_candidates_remain_valid)
{
    consensus.SharePoolTides = consensus.SharePoolCompactTides = consensus.SharePoolVarDiff = true;
    auto job = CompactEmpty();
    job.binding.share_work_bits = 3;
    const auto origin = CompactBlock(job);
    const auto proof = AssignedProof(origin, job);
    const auto check_proof = [&](const Share& value) {
        return ho::CheckShareProof(value, origin, &indexes[0], origin.nTime, consensus, Lookup(), Native());
    };
    BOOST_REQUIRE(check_proof(proof).IsValid());
    auto altered = proof;
    altered.origin.share_work_bits = 0;
    Reason(check_proof(altered), "share-binding");
    altered = proof;
    altered.origin.share_work_bits = 255;
    Reason(check_proof(altered), "share-binding");
    altered = proof;
    altered.authorization[0] ^= 1;
    Reason(check_proof(altered), "share-authorization");
    altered = proof;
    altered.origin.version = ho::COMPACT_TIDES_VERSION;
    altered.origin.share_work_bits = 0;
    altered.origin.rules = ho::RulesHash(ho::COMPACT_TIDES_VERSION);
    Reason(check_proof(altered), "version");

    auto reissued = job;
    ++reissued.binding.share_work_bits;
    auto changed = origin;
    changed.m_mm_rhs = ho::SnapshotHash(reissued);
    snapshots[changed.m_mm_rhs] = std::make_shared<const ho::Snapshot>(reissued);
    Reason(Check(changed), "owner"); // Rehashing without a new attestation cannot change work.

    auto hard = CompactEmpty(1, 0x63);
    hard.binding.share_work_bits = 255;
    const auto hard_origin = CompactBlock(hard);
    auto candidate = hard_origin;
    do { ++candidate.nNonce; } while (UintToArith256(candidate.GetHash()) > arith_uint256{}.SetCompact(candidate.nBits));
    BOOST_REQUIRE(UintToArith256(candidate.GetHash()) > UintToArith256(ho::AssignedShareTarget(255)));
    BOOST_REQUIRE(Check(candidate).IsValid());
    const Share native_only{candidate.GetBlockHeader(), hard.binding, hard.authorization};
    Reason(ho::CheckShareProof(native_only, hard_origin, &indexes[0], candidate.nTime, consensus, Lookup(), Native()), "share-target");
    // Proof eligibility and native block eligibility must remain separate routes.
    BOOST_CHECK(ho::CheckMiningJob(hard_origin, &indexes[0], consensus, Lookup(), Native(), REWARD).IsValid());
}

BOOST_AUTO_TEST_CASE(v8_mixed_work_payouts_and_persistent_history_are_exact_and_profile_scoped)
{
    namespace tides = sharepool::tides;
    consensus.SharePoolTides = consensus.SharePoolCompactTides = consensus.SharePoolVarDiff = true;
    auto alice = CompactEmpty(1, 0x71);
    alice.binding.share_work_bits = 1; // 2 expected hashes.
    const auto alice_job = CompactBlock(alice);
    auto bob = CompactEmpty(1, 0x72);
    bob.binding.share_work_bits = 3; // 8 expected hashes, same contextual native nBits.
    const auto bob_job = CompactBlock(bob);
    auto other = CompactEmpty(1, 0x73);
    other.binding.pool = uint256{uint8_t{4}};
    other.binding.share_work_bits = 2;
    CompactState(other);
    const auto other_job = CompactBlock(other);
    auto settlement = CompactEmpty();
    settlement.templates = {Record(alice_job), Record(bob_job), Record(other_job)};
    settlement.shares = {AssignedProof(alice_job, alice), AssignedProof(bob_job, bob), AssignedProof(other_job, other)};
    SortEvidence(settlement);
    CompactState(settlement);
    const auto settled = CompactBlock(settlement);
    BOOST_REQUIRE(Check(settled).IsValid());
    BOOST_REQUIRE_EQUAL(settlement.payouts.size(), 2);
    BOOST_CHECK_EQUAL(settlement.payouts[0].nValue, REWARD / 5);
    BOOST_CHECK_EQUAL(settlement.payouts[1].nValue, REWARD * 4 / 5);
    BOOST_CHECK_EQUAL(settlement.payouts[0].nValue + settlement.payouts[1].nValue, REWARD - 1); // Existing floor residue is unclaimed.
    std::vector<CTxOut> exact;
    BOOST_REQUIRE(ho::CalculateTidesPayouts(settlement, &indexes[0], settled.nBits, consensus, Lookup(), 100000, exact).IsValid());
    BOOST_REQUIRE_EQUAL(exact.size(), 2);
    BOOST_CHECK_EQUAL(exact[0].nValue, 20000);
    BOOST_CHECK_EQUAL(exact[1].nValue, 80000);
    BOOST_CHECK_EQUAL(exact[0].nValue + exact[1].nValue, 100000);
    const auto raw = ho::EncodeSnapshot(settlement);
    const auto decoded = ho::DecodeSnapshot(raw);
    BOOST_CHECK(ho::EncodeSnapshot(decoded) == raw);
    BOOST_CHECK(ho::ProfileSnapshotHash(raw, ho::VARIABLE_TIDES_VERSION) == ho::SnapshotHash(settlement));
    BOOST_CHECK(ho::ProfileSnapshotHash(raw, ho::COMPACT_TIDES_VERSION) != ho::SnapshotHash(settlement));
    for (size_t i{0}; i < decoded.shares.size(); ++i) BOOST_CHECK_EQUAL(decoded.shares[i].origin.share_work_bits, settlement.shares[i].origin.share_work_bits);

    auto forged = settlement;
    forged.shares[0].origin.share_work_bits ^= 1;
    CompactState(forged);
    BOOST_CHECK(forged.history_head != settlement.history_head);
    const auto forged_block = CompactBlock(forged);
    BOOST_CHECK(!Check(forged_block).IsValid());

    Anchor(settled);
    { LOCK(cs_main); indexes[0].nStatus = indexes[1].nStatus = BLOCK_VALID_SCRIPTS; }
    auto next = CompactEmpty(2);
    const auto expected = settlement.payouts;
    BOOST_CHECK(next.payouts == expected);
    std::vector<CTxOut> outputs;
    const auto calculate = [&](const ho::Lookup& lookup) {
        return ho::CalculateTidesPayouts(next, &indexes[1], indexes[1].nBits, consensus, lookup, REWARD, outputs);
    };
    BOOST_REQUIRE(calculate(Lookup()).IsValid());
    BOOST_CHECK(outputs == expected);
    struct RestoreReader {
        std::shared_ptr<tides::PersistentHistoryReader> previous{tides::ConfiguredPersistentHistoryReader()};
        ~RestoreReader() { tides::ConfigurePersistentHistoryReader(previous); }
    } restore;
    const auto path = m_path_root / "v8-assigned-history";
    const tides::PersistentHistoryIndex::Scope scope{consensus.hashGenesisBlock, ho::RulesHash(ho::VARIABLE_TIDES_VERSION), ho::VARIABLE_TIDES_VERSION, 1};
    {
        auto reader = std::make_shared<tides::PersistentHistoryIndex>(path, scope, tides::PersistentHistoryIndex::Options{});
        tides::ConfigurePersistentHistoryReader(reader);
        BOOST_REQUIRE(calculate(Lookup()).IsValid());
        BOOST_CHECK(outputs == expected);
        BOOST_CHECK_EQUAL(reader->GetStats().covered_blocks, 1);
        tides::ConfigurePersistentHistoryReader(nullptr);
    }
    {
        auto reader = std::make_shared<tides::PersistentHistoryIndex>(path, scope, tides::PersistentHistoryIndex::Options{});
        tides::ConfigurePersistentHistoryReader(reader);
        size_t reads{0};
        const ho::Lookup counted = [&](const uint256& hash) { ++reads; return Lookup()(hash); };
        BOOST_REQUIRE(calculate(counted).IsValid());
        BOOST_CHECK(outputs == expected);
        BOOST_CHECK(!reader->MatchesScope(consensus.hashGenesisBlock, ho::RulesHash(ho::COMPACT_TIDES_VERSION), ho::COMPACT_TIDES_VERSION, 1));
        BOOST_REQUIRE(calculate(counted).IsValid());
        BOOST_CHECK(outputs == expected);
        auto other_next = next;
        other_next.binding.pool = other.binding.pool;
        BOOST_REQUIRE(ho::CalculateTidesPayouts(other_next, &indexes[1], indexes[1].nBits, consensus, Lookup(), REWARD, outputs).IsValid());
        BOOST_REQUIRE_EQUAL(outputs.size(), 1);
        BOOST_CHECK_EQUAL(outputs[0].nValue, REWARD);
        BOOST_CHECK(std::vector<unsigned char>(outputs[0].scriptPubKey.begin(), outputs[0].scriptPubKey.end()) == other.binding.payout_script);
        tides::ConfigurePersistentHistoryReader(nullptr);
    }
    auto wrong_scope = scope;
    wrong_scope.profile = ho::COMPACT_TIDES_VERSION;
    wrong_scope.rules = ho::RulesHash(wrong_scope.profile);
    BOOST_CHECK_THROW(tides::PersistentHistoryIndex(path, wrong_scope, {}), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
